"""Simulated infrastructure, safe remediation, and recovery verification.

Nothing here touches real systems: it only mutates an in-memory dictionary.
"""
from __future__ import annotations

from typing import Optional

import numpy as np

from agent import can_execute, assess_risk, evaluate_policy, RUNBOOKS

HEALTHY, DEGRADED, CRITICAL = "HEALTHY", "DEGRADED", "CRITICAL"

# Which action actually fixes which simulated fault.
FIX_FOR_FAULT = {
    "cpu_spike": "reduce_workload",
    "memory_leak": "reset_worker_state",
    "db_connection_failure": "restore_database",
    "network_latency": "restore_network_profile",
    "app_error_spike": "restart_application",
}

# Metric values while a fault is active (mean values; small noise is added).
FAULT_STATE = {
    "cpu_spike": {"cpu": 94, "latency_ms": 150},
    "memory_leak": {"memory": 93},
    "db_connection_failure": {"error_rate": 25, "latency_ms": 500},
    "network_latency": {"latency_ms": 650, "error_rate": 2.5},
    "app_error_spike": {"error_rate": 32, "cpu": 48},
}

NORMAL_STATE = {"cpu": 35.0, "memory": 50.0, "disk": 42.0, "latency_ms": 80.0, "error_rate": 0.6}

# Verification criteria: every check must pass for RESOLVED.
CRITERIA = {
    "cpu": ("<", 80.0),
    "memory": ("<", 80.0),
    "latency_ms": ("<", 250.0),
    "error_rate": ("<", 5.0),
}


def health_of(state: dict) -> str:
    if state["cpu"] > 95 or state["memory"] > 95 or state["error_rate"] > 30 or state["latency_ms"] > 600:
        return CRITICAL
    if state["cpu"] > 85 or state["memory"] > 85 or state["error_rate"] > 10 or state["latency_ms"] > 300:
        return DEGRADED
    return HEALTHY


class SimulatedInfrastructure:
    """Holds the current simulated state of each service."""

    def __init__(self, services: list[str], seed: int = 42):
        self.rng = np.random.default_rng(seed)
        self.state = {s: dict(NORMAL_STATE) for s in services}
        self.faults: dict[str, Optional[str]] = {s: None for s in services}

    def _noisy(self, value: float, pct: float = 0.04) -> float:
        return round(float(value * (1 + self.rng.normal(0, pct))), 2)

    def snapshot(self, service: str) -> dict:
        snap = dict(self.state[service])
        snap["health"] = health_of(snap)
        snap["fault"] = self.faults[service]
        return snap

    def system_health(self) -> dict[str, str]:
        return {s: health_of(st) for s, st in self.state.items()}

    def inject_fault(self, service: str, scenario: str) -> None:
        if scenario not in FAULT_STATE:
            raise ValueError(f"Unknown scenario: {scenario}")
        self.state[service] = dict(NORMAL_STATE)
        for metric, value in FAULT_STATE[scenario].items():
            self.state[service][metric] = self._noisy(value)
        self.faults[service] = scenario

    def restore(self, service: str, snapshot: dict) -> None:
        """Rollback: put the simulated service back to a previous snapshot."""
        self.state[service] = {k: snapshot[k] for k in NORMAL_STATE}
        self.faults[service] = snapshot.get("fault")

    def execute_action(self, service: str, action: str, approved: bool, change_freeze: bool = False) -> dict:
        """Apply a remediation action if the risk policy allows it.

        Returns {executed, message, before, after}. If blocked, the state is untouched.
        """
        before = self.snapshot(service)
        checks = evaluate_policy(action, approved, change_freeze)
        allowed, reason = can_execute(action, approved, change_freeze)
        if not allowed:
            return {"executed": False, "message": reason, "action": action, "policy_checks": checks,
                    "risk": assess_risk(action), "before": before, "after": before}
        fault = self.faults[service]
        if fault and FIX_FOR_FAULT[fault] == action:
            self.state[service] = {k: self._noisy(v) for k, v in NORMAL_STATE.items()}
            self.faults[service] = None
            msg = f"Action '{action}' fixed simulated fault '{fault}'."
        else:
            msg = (f"Action '{action}' executed but does not address the active fault "
                   f"('{fault}'); state unchanged.")
        return {"executed": True, "message": msg, "action": action, "policy_checks": checks,
                "steps": RUNBOOKS[action]["steps"],
                "risk": assess_risk(action), "before": before, "after": self.snapshot(service)}


def verify_recovery(before: dict, after: dict) -> dict:
    """Check the post-remediation state against the criteria; compare with 'before'."""
    ops = {"<": lambda a, b: a < b}
    checks = []
    for metric, (op, limit) in CRITERIA.items():
        ok = ops[op](after[metric], limit)
        checks.append({"metric": metric, "before": before[metric], "after": after[metric],
                       "criterion": f"{op} {limit}", "passed": bool(ok)})
    health_ok = after["health"] == HEALTHY
    checks.append({"metric": "health", "before": before["health"], "after": after["health"],
                   "criterion": f"== {HEALTHY}", "passed": health_ok})
    return {"passed": all(c["passed"] for c in checks), "checks": checks}
