"""Synthetic server-metric generator for AegisOps.

Produces per-service, per-minute metrics with optional injected anomalies.
Everything is driven by a seed so experiments are reproducible.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable, Optional

import numpy as np
import pandas as pd

SERVICES = ["auth-service", "payment-service", "order-service", "search-service"]

SCENARIOS = [
    "cpu_spike",
    "memory_leak",
    "db_connection_failure",
    "network_latency",
    "app_error_spike",
]

SCENARIO_LABELS = {
    "cpu_spike": "CPU spike",
    "memory_leak": "Memory leak",
    "db_connection_failure": "DB connection failure",
    "network_latency": "Network latency",
    "app_error_spike": "Application error spike",
}

COLUMNS = [
    "timestamp", "service", "cpu", "memory", "disk", "latency_ms",
    "request_count", "error_rate", "log_message", "anomaly_label", "anomaly_type",
]

NORMAL_LOGS = [
    "INFO request completed successfully",
    "INFO health check OK",
    "INFO cache hit for session lookup",
    "INFO worker heartbeat received",
    "DEBUG connection pool healthy",
]

ANOMALY_LOGS = {
    "cpu_spike": [
        "WARN CPU load high: worker pool saturated",
        "WARN request queue growing, CPU throttling detected",
    ],
    "memory_leak": [
        "WARN heap usage growing steadily, GC overhead high",
        "ERROR OutOfMemory risk: worker memory not released",
    ],
    "db_connection_failure": [
        "ERROR database connection timeout after 30s",
        "ERROR connection pool exhausted: cannot reach database",
    ],
    "network_latency": [
        "WARN upstream response slow: packet loss on network link",
        "WARN network round-trip time degraded",
    ],
    "app_error_spike": [
        "ERROR HTTP 500 Internal Server Error in request handler",
        "ERROR unhandled exception in application controller",
    ],
}


def _normal_block(n: int, rng: np.random.Generator) -> dict:
    """Normal behaviour for one service: n rows of baseline metrics."""
    memory = 50 + np.cumsum(rng.normal(0, 0.4, n))
    memory = np.clip(memory - (memory.mean() - 50), 40, 62)  # keep in healthy band
    return {
        "cpu": np.clip(rng.normal(35, 6, n), 5, 70),
        "memory": memory,
        "disk": np.clip(rng.normal(42, 1.5, n), 30, 60),
        "latency_ms": np.clip(rng.normal(80, 12, n), 30, 160),
        "request_count": np.clip(rng.normal(500, 60, n), 200, 800).round(),
        "error_rate": np.clip(np.abs(rng.normal(0.6, 0.3, n)), 0, 2.0),
    }


def _apply_scenario(block: dict, scenario: str, start: int, length: int,
                    rng: np.random.Generator) -> list[str]:
    """Modify block in place for rows start..start+length. Returns log messages."""
    s = slice(start, start + length)
    if scenario == "cpu_spike":
        block["cpu"][s] = rng.uniform(88, 99, length)
        block["latency_ms"][s] = rng.normal(150, 20, length)
    elif scenario == "memory_leak":
        block["memory"][s] = np.linspace(72, 97, length) + rng.normal(0, 0.8, length)
        block["latency_ms"][s] += np.linspace(0, 40, length)
    elif scenario == "db_connection_failure":
        block["error_rate"][s] = rng.uniform(15, 35, length)
        block["latency_ms"][s] = rng.uniform(350, 650, length)
        block["request_count"][s] = block["request_count"][s] * rng.uniform(0.3, 0.6, length)
    elif scenario == "network_latency":
        block["latency_ms"][s] = rng.uniform(450, 900, length)
        block["error_rate"][s] = rng.uniform(1.5, 4.0, length)
    elif scenario == "app_error_spike":
        block["error_rate"][s] = rng.uniform(20, 45, length)
        block["cpu"][s] = block["cpu"][s] + rng.uniform(5, 15, length)
    else:
        raise ValueError(f"Unknown scenario: {scenario}")
    block["memory"] = np.clip(block["memory"], 0, 100)
    block["cpu"] = np.clip(block["cpu"], 0, 100)
    return ANOMALY_LOGS[scenario]


def generate_dataset(
    n_points: int = 300,
    seed: int = 42,
    start: Optional[datetime] = None,
    services: Iterable[str] = SERVICES,
    anomaly_plan: Optional[list[dict]] = None,
) -> pd.DataFrame:
    """Generate metrics for every service, one row per service per minute.

    anomaly_plan: list of {"scenario", "service", "start" (row index), "duration"}.
    Rows inside a planned window get anomaly_label=1 and the scenario name.
    """
    rng = np.random.default_rng(seed)
    start = start or datetime(2026, 1, 1, 9, 0, 0)
    services = list(services)
    plan = anomaly_plan or []
    frames = []
    for svc in services:
        block = _normal_block(n_points, rng)
        label = np.zeros(n_points, dtype=int)
        a_type = np.array(["none"] * n_points, dtype=object)
        logs = np.array([rng.choice(NORMAL_LOGS) for _ in range(n_points)], dtype=object)
        for item in plan:
            if item["service"] != svc:
                continue
            a_start = int(item["start"])
            a_len = int(min(item["duration"], n_points - a_start))
            if a_len <= 0:
                continue
            msgs = _apply_scenario(block, item["scenario"], a_start, a_len, rng)
            label[a_start:a_start + a_len] = 1
            a_type[a_start:a_start + a_len] = item["scenario"]
            logs[a_start:a_start + a_len] = [rng.choice(msgs) for _ in range(a_len)]
        frames.append(pd.DataFrame({
            "timestamp": [start + timedelta(minutes=i) for i in range(n_points)],
            "service": svc,
            "cpu": block["cpu"].round(2),
            "memory": block["memory"].round(2),
            "disk": block["disk"].round(2),
            "latency_ms": block["latency_ms"].round(2),
            "request_count": block["request_count"].astype(int),
            "error_rate": block["error_rate"].round(2),
            "log_message": logs,
            "anomaly_label": label,
            "anomaly_type": a_type,
        }))
    df = pd.concat(frames, ignore_index=True)
    return df.sort_values(["timestamp", "service"]).reset_index(drop=True)[COLUMNS]


def generate_labeled_test_set(seed: int = 1042, n_points: int = 400) -> pd.DataFrame:
    """A labelled evaluation set: every scenario injected on different services/times."""
    plan = [
        {"scenario": "cpu_spike", "service": SERVICES[0], "start": 60, "duration": 20},
        {"scenario": "memory_leak", "service": SERVICES[1], "start": 120, "duration": 30},
        {"scenario": "db_connection_failure", "service": SERVICES[2], "start": 190, "duration": 20},
        {"scenario": "network_latency", "service": SERVICES[3], "start": 250, "duration": 20},
        {"scenario": "app_error_spike", "service": SERVICES[0], "start": 310, "duration": 20},
        {"scenario": "cpu_spike", "service": SERVICES[2], "start": 340, "duration": 15},
        {"scenario": "network_latency", "service": SERVICES[1], "start": 30, "duration": 15},
    ]
    return generate_dataset(n_points=n_points, seed=seed, anomaly_plan=plan)
