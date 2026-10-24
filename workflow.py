"""Orchestrator: routes an incident through detection -> diagnosis -> policy -> action -> verification,
records every step in the audit log, and keeps telemetry in the SQLite telemetry store.

Kept separate from app.py so the whole workflow can be unit-tested without Streamlit.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from typing import Optional

import pandas as pd

import agent
from anomaly_detector import AnomalyDetector, HybridDetector, evaluate_events, group_events
from data_generator import SERVICES, generate_dataset, generate_labeled_test_set
from database import ACTIVE_STATUSES, Database
from remediation import SimulatedInfrastructure, verify_recovery

EVIDENCE_COLS = ["timestamp", "cpu", "memory", "disk", "latency_ms", "request_count",
                 "error_rate", "log_message"]
BUFFER_MAX_TICKS = 600
_MODEL_CACHE: dict[int, HybridDetector] = {}


def get_detector(seed: int) -> HybridDetector:
    """Train once per process (models are read-only after fitting)."""
    if seed not in _MODEL_CACHE:
        _MODEL_CACHE[seed] = HybridDetector(seed=seed).fit(
            mixed_df=generate_labeled_test_set(seed=seed),           # unlabeled use, contains anomalies
            normal_df=generate_dataset(400, seed=seed + 7),          # forecaster: normal operation
            validation_df=generate_dataset(400, seed=seed + 8))      # forecaster threshold
    return _MODEL_CACHE[seed]


class AegisOps:
    def __init__(self, db_path: str = "aegisops.db", seed: int = 42, services: Optional[list[str]] = None):
        self.seed = seed
        self.services = services or list(SERVICES)
        self.db = Database(db_path)
        self.infra = SimulatedInfrastructure(self.services, seed=seed)
        self.detector = get_detector(seed)
        self._tick_counter = int(self.db.get_setting("tick_counter", "0"))
        self.buffer = self.db.load_metrics(BUFFER_MAX_TICKS)
        if self.buffer.empty:                                         # first start: seed the telemetry store
            self.buffer = generate_dataset(120, seed=seed + 1, services=self.services)
            self.db.save_metrics(self.buffer)
        self._eval_cache: Optional[dict] = None
        self._scored_cache: Optional[tuple] = None

    # ------------------------------------------------------------ policy settings
    @property
    def change_freeze(self) -> bool:
        return self.db.get_setting("change_freeze", "0") == "1"

    def set_change_freeze(self, on: bool, actor: str = "system") -> None:
        self.db.set_setting("change_freeze", "1" if on else "0")
        self.db.log_event(actor, "POLICY_CHANGE", f"Change freeze {'ENABLED' if on else 'DISABLED'}")

    # ------------------------------------------------------------ telemetry
    def _advance(self, n_ticks: int) -> None:
        """Append n minutes of metrics. Services with an active fault keep showing it."""
        self._tick_counter += 1
        self.db.set_setting("tick_counter", str(self._tick_counter))
        plan = [{"scenario": f, "service": s, "start": 0, "duration": n_ticks}
                for s, f in self.infra.faults.items() if f]
        start = self.buffer["timestamp"].max() + timedelta(minutes=1)
        new = generate_dataset(n_ticks, seed=self.seed + 100 + self._tick_counter, start=start,
                               services=self.services, anomaly_plan=plan)
        self.db.save_metrics(new)
        buf = pd.concat([self.buffer, new], ignore_index=True)
        cutoff = buf["timestamp"].max() - timedelta(minutes=BUFFER_MAX_TICKS - 1)
        self.buffer = buf[buf["timestamp"] >= cutoff].reset_index(drop=True)

    def inject_anomaly(self, scenario: str, service: str, actor: str = "system") -> None:
        """Inject a fault into the simulated infrastructure and the metric stream."""
        if service not in self.services:
            raise ValueError(f"Unknown service: {service}")
        self._advance(10)                      # some normal minutes first
        self.infra.inject_fault(service, scenario)
        self._advance(15)                      # then the anomaly is visible in the stream
        self.db.log_event(actor, "FAULT_INJECTED", f"Scenario '{scenario}' injected (simulation)", service=service)

    def scored(self) -> pd.DataFrame:
        key = (len(self.buffer), self.buffer["timestamp"].max())
        if self._scored_cache is None or self._scored_cache[0] != key:
            self._scored_cache = (key, self.detector.predict(self.buffer))
        return self._scored_cache[1]

    def recent_logs(self, service: Optional[str] = None, level: Optional[str] = None, n: int = 200) -> pd.DataFrame:
        df = self.buffer
        if service:
            df = df[df["service"] == service]
        if level:
            df = df[df["log_message"].str.upper().str.startswith(level.upper())]
        return df[["timestamp", "service", "log_message"]].tail(n).iloc[::-1]

    # ------------------------------------------------------------ detection agent
    def run_detection(self, actor: str = "system") -> list[str]:
        """Score the stream, group events, create incidents for new events."""
        created = []
        scored = self.scored()
        for ev in group_events(scored):
            start_ts = ev["start"].isoformat()
            if self.db.detection_exists(ev["service"], start_ts):
                continue
            rows = ev["rows"]
            summary = agent.summarize_metrics(rows)
            evidence = {"summary": summary,
                        "rows": [{**r, "timestamp": str(r["timestamp"])}
                                 for r in rows[EVIDENCE_COLS].to_dict("records")]}
            inc_id = self.db.create_incident(
                service=ev["service"], severity=agent.severity_from_summary(summary),
                timestamp=start_ts, metric_evidence=evidence,
                log_messages=rows["log_message"].tolist())
            self.db.record_detection(ev["service"], start_ts, ev["end"].isoformat(),
                                     ev["n_flagged"], ev["max_score"], inc_id)
            by = ", ".join(sorted(set(scored.loc[rows.index, "detector"]) - {"-"})) if "detector" in scored else "detector"
            self.db.log_event(actor, "INCIDENT_CREATED",
                              f"Anomaly of {ev['n_flagged']} consecutive minutes (max score {ev['max_score']:.2f}); flagged by {by}",
                              incident_id=inc_id, service=ev["service"])
            created.append(inc_id)
        return created

    # ------------------------------------------------------------ diagnosis agent
    def investigate(self, incident_id: str, actor: str = "system") -> agent.Investigation:
        inc = self._get(incident_id)
        if inc["status"] not in ACTIVE_STATUSES:
            raise ValueError(f"{incident_id} is {inc['status']}; cannot investigate.")
        self.db.update_incident(incident_id, status="INVESTIGATING")
        rows = pd.DataFrame(inc["metric_evidence"]["rows"])
        logs = inc["log_messages"]
        calls: list[dict] = []

        summ = agent.summarize_metrics(rows)                                          # tool 1 (read-only)
        calls.append({"tool": "get_metric_summary", "args": f"service={inc['service']}, rows={len(rows)}",
                      "result": f"CPU {summ['cpu_mean']}%, memory peak {summ['memory_max']}%, "
                                f"latency {summ['latency_mean']} ms, errors {summ['error_rate_mean']}%"})
        bad = [m for m in logs if m.upper().startswith(("WARN", "ERROR"))]            # tool 2
        calls.append({"tool": "search_logs", "args": "level in (WARN, ERROR)",
                      "result": f"{len(bad)} of {len(logs)} lines"
                                + (f"; most common: '{pd.Series(bad).value_counts().index[0]}'" if bad else "")})
        health = {s: h for s, h in self.infra.system_health().items() if s != inc["service"]}   # tool 3
        calls.append({"tool": "check_dependency_health", "args": "all other services",
                      "result": ", ".join(f"{s}: {h}" for s, h in health.items())})

        inv = agent.investigate(rows, self.detector.baseline, logs)

        similar = [i for i in self.db.list_incidents()                               # tool 4
                   if i["anomaly_type"] == inv.anomaly_type and i["incident_id"] != incident_id
                   and i["status"] in ("RESOLVED", "FAILED")]
        calls.append({"tool": "find_similar_incidents", "args": f"anomaly_type={inv.anomaly_type}",
                      "result": f"{len(similar)} found" + (": " + ", ".join(f"{i['incident_id']} ({i['status']})" for i in similar[:3]) if similar else "")})
        if similar:
            inv.evidence.append(f"{len(similar)} earlier incident(s) with the same signature: "
                                + ", ".join(f"{i['incident_id']} ended {i['status']}" for i in similar[:3]))
        inv.tool_calls = calls

        self.db.save_investigation(incident_id, inv.to_dict())
        self.db.update_incident(
            incident_id, anomaly_type=inv.anomaly_type, severity=inv.severity,
            root_cause=inv.root_cause, recommended_action=inv.recommended_action,
            risk_level=inv.risk_level,
            status="WAITING_APPROVAL" if inv.needs_approval else "INVESTIGATING")
        self.db.log_event(actor, "INVESTIGATED",
                          f"{inv.root_cause} (support {inv.confidence_score:.2f}); action {inv.recommended_action} "
                          f"[{inv.risk_level}]; {len(calls)} read-only tool calls", incident_id=incident_id, service=inc["service"])
        return inv

    # ------------------------------------------------------------ approval
    def approve(self, incident_id: str, decided_by: str = "operator") -> None:
        inc = self._get(incident_id)
        if inc["status"] != "WAITING_APPROVAL":
            raise ValueError(f"{incident_id} is not waiting for approval (status {inc['status']}).")
        self.db.record_approval(incident_id, inc["recommended_action"], "APPROVED", decided_by)
        self.db.update_incident(incident_id, status="INVESTIGATING")
        self.db.log_event(decided_by, "APPROVED", f"Approved action '{inc['recommended_action']}'",
                          incident_id=incident_id, service=inc["service"])

    def reject(self, incident_id: str, reason: str = "", decided_by: str = "operator") -> None:
        inc = self._get(incident_id)
        if inc["status"] != "WAITING_APPROVAL":
            raise ValueError(f"{incident_id} is not waiting for approval (status {inc['status']}).")
        self.db.record_approval(incident_id, inc["recommended_action"], "REJECTED", decided_by, reason)
        self.db.update_incident(incident_id, status="OPEN")   # still active; needs manual follow-up
        self.db.log_event(decided_by, "REJECTED", f"Rejected action '{inc['recommended_action']}'. {reason}",
                          incident_id=incident_id, service=inc["service"])

    # ------------------------------------------------------------ action agent
    def remediate(self, incident_id: str, actor: str = "system") -> dict:
        """Execute the recommended runbook - only if every policy check passes."""
        inc = self._get(incident_id)
        action = inc["recommended_action"]
        if not action:
            raise ValueError(f"{incident_id} has not been investigated yet.")
        appr = self.db.latest_approval(incident_id, action)
        approved = bool(appr and appr["decision"] == "APPROVED")
        result = self.infra.execute_action(inc["service"], action, approved, change_freeze=self.change_freeze)
        self.db.record_remediation(incident_id, result)
        self.db.log_event(actor, "REMEDIATION_EXECUTED" if result["executed"] else "REMEDIATION_BLOCKED",
                          result["message"], incident_id=incident_id, service=inc["service"])
        return result

    def verify(self, incident_id: str, actor: str = "system") -> dict:
        """Re-measure the service; RESOLVED if criteria pass, otherwise roll back, escalate and mark FAILED."""
        inc = self._get(incident_id)
        rem = [r for r in self.db.related(incident_id)["remediations"] if r["executed"]]
        if not rem:
            raise ValueError(f"No executed remediation for {incident_id}; nothing to verify.")
        before = rem[-1]["before_state"]
        after = self.infra.snapshot(inc["service"])
        result = verify_recovery(before, after)
        result["before"], result["after"], result["rolled_back"] = before, after, False
        self.db.record_verification(incident_id, result)
        if result["passed"]:
            self.db.update_incident(incident_id, status="RESOLVED")
            self.db.log_event(actor, "VERIFIED", "All recovery checks passed; incident RESOLVED",
                              incident_id=incident_id, service=inc["service"])
        else:
            self.infra.restore(inc["service"], before)          # rollback procedure
            result["rolled_back"] = True
            self.db.update_incident(incident_id, status="FAILED")
            self.db.log_event(actor, "ROLLBACK", "Verification failed; simulated state rolled back to pre-action snapshot",
                              incident_id=incident_id, service=inc["service"])
            self.db.log_event(actor, "ESCALATED", "Incident escalated to a human operator", incident_id=incident_id,
                              service=inc["service"])
        self._advance(10)                      # stream continues: healthy or still faulty
        return result

    # ------------------------------------------------------------ orchestrator
    def run_cycle(self, actor: str = "system") -> dict:
        """One orchestrator cycle: detect -> investigate every new incident. Remediation stays gated by policy."""
        t0 = time.perf_counter()
        created = self.run_detection(actor)
        t1 = time.perf_counter()
        investigated = []
        for iid in created:
            self.investigate(iid, actor)
            investigated.append(iid)
        t2 = time.perf_counter()
        waiting = [i["incident_id"] for i in self.db.list_incidents("WAITING_APPROVAL")]
        summary = {"new_incidents": created, "investigated": investigated, "waiting_approval": waiting,
                   "detect_ms": round((t1 - t0) * 1000), "diagnose_ms": round((t2 - t1) * 1000)}
        self.db.log_event(actor, "ORCHESTRATOR_CYCLE",
                          f"{len(created)} new incident(s), {len(investigated)} investigated, {len(waiting)} awaiting approval")
        return summary

    # ------------------------------------------------------------ analytics
    def evaluate_model(self) -> dict:
        """Row-level metrics for Isolation Forest, forecaster and the hybrid, plus event-level results."""
        if self._eval_cache is None:
            scored = self.detector.predict(generate_labeled_test_set(seed=self.seed + 1000))
            out = {"n_rows": int(len(scored)), "forecast_threshold": round(self.detector.forecaster.threshold, 3)}
            for name, col in (("isolation_forest", "is_anomaly_if"), ("forecaster", "forecast_flag"), ("hybrid", "is_anomaly")):
                x = scored.copy(); x["is_anomaly"] = scored[col]
                out[name] = AnomalyDetector.evaluate(x)
            out["events"] = evaluate_events(scored)
            self._eval_cache = out
        return self._eval_cache

    def mean_resolution_seconds(self) -> Optional[float]:
        done = [i for i in self.db.list_incidents() if i["status"] == "RESOLVED"]
        if not done:
            return None
        fmt = "%Y-%m-%dT%H:%M:%S"
        return sum((datetime.strptime(i["updated_at"], fmt) - datetime.strptime(i["created_at"], fmt)).total_seconds()
                   for i in done) / len(done)

    def _get(self, incident_id: str) -> dict:
        inc = self.db.get_incident(incident_id)
        if inc is None:
            raise ValueError(f"Unknown incident {incident_id}")
        return inc
