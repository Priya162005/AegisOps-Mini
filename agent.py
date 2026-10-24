"""Rule-based investigation agent and risk policy.

This is NOT an LLM. It is a transparent set of if/else rules that read the stored
metrics and log lines of an incident and explain which numbers triggered each rule.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

import numpy as np
import pandas as pd

# ---------------------------------------------------------------- risk policy
LOW, MEDIUM, HIGH = "LOW", "MEDIUM", "HIGH"

ACTION_CATALOG = {
    # key: (description, risk level)
    "collect_diagnostics": ("Collect extra diagnostics and flag for manual review (read-only)", LOW),
    "reduce_workload": ("Reduce simulated workload (throttle traffic / scale out)", MEDIUM),
    "reset_worker_state": ("Reset simulated worker state (recycle leaking workers)", MEDIUM),
    "restore_database": ("Restore simulated database availability (reset connection pool)", MEDIUM),
    "restore_network_profile": ("Restore the normal simulated network profile", MEDIUM),
    "restart_application": ("Restart the simulated application", MEDIUM),
    "restart_production_host": ("Restart a production host (never executed by AegisOps)", HIGH),
}


# Runbook library: ordered steps, parameter bounds (value, max) and rollback procedure.
RUNBOOKS = {
    "collect_diagnostics": {"steps": ["Capture thread dump", "Collect recent logs", "Flag incident for manual review"],
                            "params": {}, "rollback": ["Nothing to roll back (read-only)"]},
    "reduce_workload": {"steps": ["Enable request throttling", "Scale out workers by a bounded factor", "Drain hot queue"],
                        "params": {"throttle_pct": (30, 50), "scale_factor": (2, 3)},
                        "rollback": ["Disable throttling", "Scale back to original worker count"]},
    "reset_worker_state": {"steps": ["Mark leaking workers unhealthy", "Recycle workers one at a time", "Re-check heap usage"],
                           "params": {"max_workers_recycled": (2, 4)},
                           "rollback": ["Restore previous worker pool configuration"]},
    "restore_database": {"steps": ["Reset connection pool", "Re-establish database connection", "Run health query"],
                         "params": {"pool_size": (20, 50)}, "rollback": ["Restore previous pool settings"]},
    "restore_network_profile": {"steps": ["Reapply normal network profile", "Clear injected delay", "Check round-trip time"],
                                "params": {}, "rollback": ["Reapply previous network profile"]},
    "restart_application": {"steps": ["Drain traffic", "Restart application process", "Wait for health check"],
                            "params": {"grace_seconds": (30, 120)}, "rollback": ["Restore previous release / process state"]},
    "restart_production_host": {"steps": ["Reboot host"], "params": {}, "rollback": ["Not available"]},
}


def assess_risk(action: str) -> str:
    """Unknown actions fail closed as HIGH."""
    return ACTION_CATALOG.get(action, ("", HIGH))[1]


def requires_approval(risk: str) -> bool:
    return risk == MEDIUM


def evaluate_policy(action: str, approved: bool, change_freeze: bool = False) -> list[dict]:
    """Policy engine: returns the list of checks (each passed/failed with a reason)."""
    known = action in ACTION_CATALOG
    risk = assess_risk(action)
    checks = [{"check": "Allow-list", "passed": known,
               "detail": "Action is on the allow-list." if known else f"Action '{action}' is not on the allow-list."}]
    params = RUNBOOKS.get(action, {}).get("params", {})
    in_bounds = all(v <= mx for v, mx in params.values())
    checks.append({"check": "Argument bounds", "passed": known and in_bounds,
                   "detail": ", ".join(f"{k}={v} (max {mx})" for k, (v, mx) in params.items()) or "No parameters."})
    checks.append({"check": "Risk level", "passed": risk != HIGH,
                   "detail": "HIGH-risk actions are never executed by AegisOps." if risk == HIGH else f"Risk is {risk}."})
    checks.append({"check": "Change freeze", "passed": not change_freeze,
                   "detail": "Change freeze is ACTIVE: remediation is blocked." if change_freeze else "No change freeze."})
    needs = requires_approval(risk)
    checks.append({"check": "Approval gate", "passed": (not needs) or approved,
                   "detail": ("MEDIUM-risk action requires an explicit approval." if needs and not approved
                              else "Approved by a human operator." if needs else "No approval required (low risk).")})
    return checks


def can_execute(action: str, approved: bool, change_freeze: bool = False) -> tuple[bool, str]:
    """Central policy gate used by the remediation layer."""
    failed = [c for c in evaluate_policy(action, approved, change_freeze) if not c["passed"]]
    return (False, failed[0]["detail"]) if failed else (True, "Allowed by risk policy.")


# ---------------------------------------------------------------- investigation
@dataclass
class Investigation:
    anomaly_type: str
    root_cause: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    recommended_action: str = "collect_diagnostics"
    action_description: str = ""
    risk_level: str = LOW
    severity: str = "MEDIUM"
    needs_approval: bool = False
    confidence_score: float = 0.0
    hypotheses: list = field(default_factory=list)
    tool_calls: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _slope(values: np.ndarray) -> float:
    return float(np.polyfit(np.arange(len(values)), values, 1)[0]) if len(values) > 1 else 0.0


def summarize_metrics(rows: pd.DataFrame) -> dict:
    """Numeric summary of an incident window (also stored as metric evidence)."""
    return {
        "n_rows": int(len(rows)),
        "cpu_mean": round(float(rows["cpu"].mean()), 2), "cpu_max": round(float(rows["cpu"].max()), 2),
        "memory_mean": round(float(rows["memory"].mean()), 2), "memory_max": round(float(rows["memory"].max()), 2),
        "memory_slope_per_min": round(_slope(rows["memory"].to_numpy()), 3),
        "latency_mean": round(float(rows["latency_ms"].mean()), 2), "latency_max": round(float(rows["latency_ms"].max()), 2),
        "error_rate_mean": round(float(rows["error_rate"].mean()), 2), "error_rate_max": round(float(rows["error_rate"].max()), 2),
        "requests_mean": round(float(rows["request_count"].mean()), 1),
    }


def _matching_logs(logs: list[str], keywords: list[str]) -> list[str]:
    return [m for m in logs if any(k in m.lower() for k in keywords)]


def _severity(m: dict) -> str:
    """Heuristic severity from the incident's metric summary."""
    if (m["cpu_mean"] > 95 or m["memory_max"] > 95 or m["error_rate_mean"] > 28
            or m["latency_mean"] > 600):
        return "CRITICAL"
    if (m["cpu_mean"] > 85 or m["memory_max"] > 85 or m["error_rate_mean"] > 10
            or m["latency_mean"] > 300):
        return "HIGH"
    return "MEDIUM"


severity_from_summary = _severity


def _investigate_rules(rows: pd.DataFrame, baseline: dict, logs: Optional[list[str]] = None) -> Investigation:
    """Read metrics + logs of an incident window and return a diagnosis with evidence.

    Rule order matters: log-based database evidence first (database failures also raise
    latency/errors), then memory trend, CPU, latency, and finally error rate.
    """
    if rows.empty:
        raise ValueError("Cannot investigate an incident with no metric rows.")
    logs = logs if logs is not None else rows["log_message"].tolist()
    m = summarize_metrics(rows)
    sev = _severity(m)
    b = baseline

    def delta(key_metric: str, base_key: str, unit: str = "") -> str:
        return f"{m[key_metric]}{unit} vs baseline {b[base_key]:.1f}{unit}"

    # Only WARN/ERROR lines count as failure evidence ("DEBUG connection pool healthy" must not),
    # and the metrics must corroborate the logs.
    problem_logs = [m for m in logs if m.upper().startswith(("WARN", "ERROR"))]
    db_logs = _matching_logs(problem_logs, ["database", "connection pool", "db connection"])
    ev: list[str] = []
    if db_logs and (m["error_rate_mean"] > 5 or m["latency_mean"] > 250):
        ev.append(f"{len(db_logs)} of {len(logs)} log lines mention database/connection-pool problems, e.g. '{db_logs[0]}'")
        ev.append(f"Mean error rate {delta('error_rate_mean', 'error_rate', '%')}")
        ev.append(f"Mean latency {delta('latency_mean', 'latency_ms', ' ms')}")
        return _build("db_connection_failure", "Probable database connectivity failure", "HIGH",
                      ev, "restore_database", sev)

    mem_rise = m["memory_max"] - b["memory"]
    if m["memory_slope_per_min"] > 0.3 and m["memory_max"] > 75 and m["cpu_mean"] < 80:
        ev.append(f"Memory climbs {m['memory_slope_per_min']} %/min, peaking at {m['memory_max']}% (baseline {b['memory']:.1f}%, +{mem_rise:.1f})")
        gc = _matching_logs(logs, ["heap", "gc", "memory", "outofmemory"])
        if gc:
            ev.append(f"{len(gc)} log lines mention memory/heap pressure, e.g. '{gc[0]}'")
        return _build("memory_leak", "Probable memory leak (steadily increasing memory)",
                      "HIGH" if gc else "MEDIUM", ev, "reset_worker_state", sev)

    if m["cpu_mean"] > 85:
        ev.append(f"Mean CPU {delta('cpu_mean', 'cpu', '%')}, peak {m['cpu_max']}%")
        cl = _matching_logs(logs, ["cpu", "saturated", "throttl"])
        if cl:
            ev.append(f"{len(cl)} log lines mention CPU saturation, e.g. '{cl[0]}'")
        return _build("cpu_spike", "Probable CPU overload", "HIGH" if cl else "MEDIUM",
                      ev, "reduce_workload", sev)

    if m["latency_mean"] > 300 and m["error_rate_mean"] < 8:
        ev.append(f"Mean latency {delta('latency_mean', 'latency_ms', ' ms')}, peak {m['latency_max']} ms")
        ev.append(f"Error rate only {m['error_rate_mean']}% and CPU {m['cpu_mean']}% - not an application or CPU problem")
        nl = _matching_logs(logs, ["network", "packet", "upstream", "round-trip"])
        if nl:
            ev.append(f"{len(nl)} log lines mention network degradation, e.g. '{nl[0]}'")
        return _build("network_latency", "Probable network degradation", "HIGH" if nl else "MEDIUM",
                      ev, "restore_network_profile", sev)

    if m["error_rate_mean"] > 10:
        ev.append(f"Mean error rate {delta('error_rate_mean', 'error_rate', '%')}, peak {m['error_rate_max']}%")
        el = _matching_logs(logs, ["500", "exception", "error in"])
        if el:
            ev.append(f"{len(el)} log lines show HTTP 500 / unhandled exceptions, e.g. '{el[0]}'")
        return _build("app_error_spike", "Probable application error condition", "HIGH" if el else "MEDIUM",
                      ev, "restart_application", sev)

    ev.append("No rule matched the observed metrics and logs; no root cause is claimed.")
    ev.append(f"CPU {m['cpu_mean']}%, memory {m['memory_mean']}%, latency {m['latency_mean']} ms, errors {m['error_rate_mean']}%")
    return _build("unknown", "Undetermined - manual review needed", "LOW", ev, "collect_diagnostics", sev)


def _build(a_type, cause, conf, ev, action, sev) -> Investigation:
    desc, risk = ACTION_CATALOG[action]
    return Investigation(
        anomaly_type=a_type, root_cause=cause, confidence=conf, evidence=ev,
        recommended_action=action, action_description=desc, risk_level=risk,
        severity=sev, needs_approval=requires_approval(risk),
    )


CAUSE_LABELS = {
    "cpu_spike": "CPU overload", "memory_leak": "Memory leak", "db_connection_failure": "Database connectivity failure",
    "network_latency": "Network degradation", "app_error_spike": "Application error condition",
}


def _clip(x: float) -> float:
    return float(min(1.0, max(0.0, x)))


def rank_hypotheses(m: dict, b: dict, logs: list[str]) -> list[dict]:
    """Support score (0-1) for every known cause, computed from the incident's own metrics and logs.

    This is a transparent heuristic score, not a calibrated probability.
    """
    problem = [x for x in logs if x.upper().startswith(("WARN", "ERROR"))]
    db_frac = len(_matching_logs(problem, ["database", "connection pool", "db connection"])) / max(1, len(logs))
    scores = {
        "cpu_spike": (_clip((m["cpu_mean"] - b["cpu"]) / (95 - b["cpu"])),
                      f"mean CPU {m['cpu_mean']}% vs baseline {b['cpu']:.1f}%"),
        "memory_leak": (_clip((m["memory_max"] - b["memory"]) / (95 - b["memory"])) * (1.0 if m["memory_slope_per_min"] > 0.3 else 0.4),
                        f"memory peak {m['memory_max']}%, slope {m['memory_slope_per_min']} %/min"),
        "db_connection_failure": (0.5 * _clip(db_frac * 1.5) + 0.5 * _clip((m["error_rate_mean"] - b["error_rate"]) / (25 - b["error_rate"])) * (1.0 if db_frac > 0 else 0.5),
                                  f"{db_frac:.0%} of log lines are database errors, error rate {m['error_rate_mean']}%"),
        "network_latency": (_clip((m["latency_mean"] - b["latency_ms"]) / (650 - b["latency_ms"])) * (1.0 if m["error_rate_mean"] < 8 else 0.4),
                            f"mean latency {m['latency_mean']} ms vs baseline {b['latency_ms']:.0f} ms, errors {m['error_rate_mean']}%"),
        "app_error_spike": (_clip((m["error_rate_mean"] - b["error_rate"]) / (30 - b["error_rate"])),
                            f"mean error rate {m['error_rate_mean']}% vs baseline {b['error_rate']:.1f}%"),
    }
    ranked = sorted(scores.items(), key=lambda kv: kv[1][0], reverse=True)
    return [{"cause": k, "label": CAUSE_LABELS[k], "support": round(v[0], 2), "evidence": v[1]} for k, v in ranked]


def investigate(rows: pd.DataFrame, baseline: dict, logs: Optional[list[str]] = None) -> Investigation:
    """Rule-based diagnosis plus a ranked list of competing hypotheses with support scores."""
    inv = _investigate_rules(rows, baseline, logs)
    logs = logs if logs is not None else rows["log_message"].tolist()
    inv.hypotheses = rank_hypotheses(summarize_metrics(rows), baseline, logs)
    match = [h for h in inv.hypotheses if h["cause"] == inv.anomaly_type]
    inv.confidence_score = match[0]["support"] if match else inv.hypotheses[0]["support"] * 0.5
    return inv
