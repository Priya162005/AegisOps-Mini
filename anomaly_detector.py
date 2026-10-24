"""Isolation Forest anomaly detection + event grouping + honest evaluation."""
from __future__ import annotations

from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ["cpu", "memory", "disk", "latency_ms", "request_count", "error_rate"]


class AnomalyDetector:
    """Wraps StandardScaler + IsolationForest.

    Trained, without labels, on metric data that contains a mix of normal and abnormal
    behaviour (as real monitoring data would). `contamination` is the assumed fraction
    of anomalous rows in the training data and sets the decision threshold. It was
    chosen on a separate validation set (see README) and works best when it is close
    to the true anomaly rate.
    """

    def __init__(self, contamination: float = 0.09, n_estimators: int = 200, seed: int = 42):
        self.contamination = contamination
        self.seed = seed
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=n_estimators, contamination=contamination, random_state=seed
        )
        self.baseline: dict[str, float] = {}
        self.is_fitted = False

    def fit(self, df: pd.DataFrame) -> "AnomalyDetector":
        X = self.scaler.fit_transform(df[FEATURES])
        self.model.fit(X)
        self.baseline = {f: float(df[f].median()) for f in FEATURES}  # median: robust to anomalies in training data
        self.is_fitted = True
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return a copy with `anomaly_score` (higher = more anomalous) and `is_anomaly`."""
        if not self.is_fitted:
            raise RuntimeError("Detector must be fitted before predict().")
        out = df.copy()
        if out.empty:
            out["anomaly_score"] = []
            out["is_anomaly"] = []
            return out
        X = self.scaler.transform(out[FEATURES])
        out["anomaly_score"] = -self.model.decision_function(X)  # >0 => anomalous
        out["is_anomaly"] = (self.model.predict(X) == -1).astype(int)
        return out

    @staticmethod
    def evaluate(scored: pd.DataFrame) -> dict:
        """Compare predictions with synthetic labels. All numbers computed, never hard-coded."""
        y, p = scored["anomaly_label"].to_numpy(), scored["is_anomaly"].to_numpy()
        tp = int(((y == 1) & (p == 1)).sum())
        fp = int(((y == 0) & (p == 1)).sum())
        fn = int(((y == 1) & (p == 0)).sum())
        tn = int(((y == 0) & (p == 0)).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        per_scenario = {}
        for sc, g in scored[scored["anomaly_label"] == 1].groupby("anomaly_type"):
            per_scenario[sc] = round(float(g["is_anomaly"].mean()), 3)
        return {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "false_positive_rate": round(fpr, 4),
            "per_scenario_recall": per_scenario,
            "n_rows": int(len(scored)), "n_anomalous_rows": int(y.sum()),
        }

    LIMITATIONS = [
        "Unsupervised: it flags 'unusual', not 'what is wrong' - root cause comes from the agent's rules.",
        "contamination must roughly match the real anomaly rate; if it is too low anomalies are missed, too high gives false alarms.",
        "Trained on synthetic data with simple Gaussian noise; real servers have seasonality and drift.",
        "Gradual anomalies (e.g. the early phase of a memory leak) look normal until values drift far enough.",
        "Treats each minute independently - no temporal context beyond the event grouping step.",
        "The contamination parameter trades false alarms against missed detections and must be tuned.",
    ]


def group_events(scored: pd.DataFrame, min_points: int = 3, max_gap: int = 1) -> list[dict]:
    """Group flagged rows into events per service.

    Flagged rows at most `max_gap` minutes apart are merged (max_gap=1 means consecutive rows);
    events with fewer than `min_points` flagged rows are ignored (suppresses isolated false
    positives). When the hybrid detector is used, the evidence window is trimmed so it starts
    and ends on rows the Isolation Forest itself flagged (forecast-only flags at the edges are
    usually just the "echo" of an anomaly in the forecaster's input window).
    """
    events: list[dict] = []
    flagged = scored[scored["is_anomaly"] == 1]
    for svc, g in flagged.groupby("service"):
        g = g.sort_values("timestamp")
        current: list[pd.Series] = []
        last_ts: Optional[pd.Timestamp] = None
        for _, row in g.iterrows():
            ts = pd.Timestamp(row["timestamp"])
            if last_ts is not None and (ts - last_ts) > pd.Timedelta(minutes=max_gap):
                _close_event(events, svc, current, scored, min_points)
                current = []
            current.append(row)
            last_ts = ts
        _close_event(events, svc, current, scored, min_points)
    return sorted(events, key=lambda e: e["start"])


def _close_event(events, svc, rows, scored, min_points):
    if len(rows) < min_points:
        return
    start, end = pd.Timestamp(rows[0]["timestamp"]), pd.Timestamp(rows[-1]["timestamp"])
    window = scored[(scored["service"] == svc) & (scored["timestamp"] >= start)
                    & (scored["timestamp"] <= end)]
    if "is_anomaly_if" in window.columns:
        flag = window["is_anomaly_if"].to_numpy() == 1
        if flag.sum() >= 2:
            first, last = int(flag.argmax()), len(flag) - 1 - int(flag[::-1].argmax())
            window = window.iloc[first:last + 1]
    events.append({
        "service": svc, "start": start, "end": end,
        "n_flagged": len(rows),
        "max_score": float(max(r["anomaly_score"] for r in rows)),
        "rows": window,
    })


def evaluate_events(scored: pd.DataFrame, min_points: int = 3, max_gap: int = 1) -> dict:
    """Event-level check: how many injected anomaly windows produced a detected event,
    and how many detected events do not overlap any injected window (false incidents)."""
    truth = scored.copy()
    truth["is_anomaly"] = truth["anomaly_label"]
    truth["anomaly_score"] = 0.0
    true_events = group_events(truth, min_points=1, max_gap=1)
    found = group_events(scored, min_points=min_points, max_gap=max_gap)

    def overlap(a, b):
        return a["service"] == b["service"] and a["start"] <= b["end"] and b["start"] <= a["end"]

    detected = [t for t in true_events if any(overlap(t, f) for f in found)]
    false_events = [f for f in found if not any(overlap(f, t) for t in true_events)]
    return {
        "injected_events": len(true_events),
        "detected_events": len(detected),
        "event_recall": round(len(detected) / len(true_events), 4) if true_events else 0.0,
        "false_incidents": len(false_events),
    }


# ====================================================================== hybrid detector
FORECAST_FEATURES = ["cpu", "memory", "latency_ms", "request_count", "error_rate"]


class ForecastDetector:
    """Neural next-minute forecaster. A large forecast error means 'behaviour not learned as normal'.

    Uses scikit-learn's MLPRegressor on a sliding window of the previous `lags` minutes
    (a small feed-forward network, not an LSTM). The threshold is the chosen percentile of
    the residuals on the (normal) training data.
    """

    def __init__(self, lags: int = 5, percentile: float = 99.7, seed: int = 42):
        from sklearn.neural_network import MLPRegressor
        self.lags, self.percentile, self.seed = lags, percentile, seed
        self.scaler = StandardScaler()
        self.model = MLPRegressor(hidden_layer_sizes=(32, 16), alpha=1e-2, max_iter=800, early_stopping=True,
                                  n_iter_no_change=20, random_state=seed)
        self.threshold = 0.0
        self.is_fitted = False

    def _windows(self, df: pd.DataFrame):
        """Yield (row_positions, X, y) per service; row_positions index into df."""
        Z = self.scaler.transform(df[FORECAST_FEATURES])
        for _, idx in df.groupby("service").indices.items():
            idx = idx[np.argsort(df["timestamp"].to_numpy()[idx])]
            if len(idx) <= self.lags:
                continue
            X = np.stack([Z[idx[i - self.lags:i]].ravel() for i in range(self.lags, len(idx))])
            yield idx[self.lags:], X, Z[idx[self.lags:]]

    def _residuals(self, df: pd.DataFrame) -> np.ndarray:
        parts = list(self._windows(df))
        X = np.vstack([p[1] for p in parts]); y = np.vstack([p[2] for p in parts])
        return np.sqrt(((self.model.predict(X) - y) ** 2).mean(axis=1))

    def fit(self, df: pd.DataFrame, validation_df: Optional[pd.DataFrame] = None) -> "ForecastDetector":
        """Fit on normal data; set the threshold from separate normal validation data
        (training residuals are too optimistic and would cause many false alarms)."""
        self.scaler.fit(df[FORECAST_FEATURES])
        parts = list(self._windows(df))
        self.model.fit(np.vstack([p[1] for p in parts]), np.vstack([p[2] for p in parts]))
        self.threshold = float(np.percentile(self._residuals(validation_df if validation_df is not None else df),
                                             self.percentile))
        self.is_fitted = True
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        if not self.is_fitted:
            raise RuntimeError("Forecaster must be fitted before predict().")
        out = df.copy().reset_index(drop=True)
        out["forecast_error"] = 0.0
        for pos, X, y in self._windows(out):
            out.loc[pos, "forecast_error"] = np.sqrt(((self.model.predict(X) - y) ** 2).mean(axis=1))
        out["forecast_flag"] = (out["forecast_error"] > self.threshold).astype(int)
        return out


class HybridDetector:
    """Isolation Forest OR forecast-error threshold (as in the system design)."""

    def __init__(self, contamination: float = 0.09, seed: int = 42):
        self.iforest = AnomalyDetector(contamination=contamination, seed=seed)
        self.forecaster = ForecastDetector(seed=seed)
        self.is_fitted = False

    @property
    def baseline(self) -> dict:
        return self.iforest.baseline

    def fit(self, mixed_df: pd.DataFrame, normal_df: pd.DataFrame,
            validation_df: Optional[pd.DataFrame] = None) -> "HybridDetector":
        self.iforest.fit(mixed_df)                        # unsupervised, data contains anomalies
        self.forecaster.fit(normal_df, validation_df)     # trained on normal operation only
        self.is_fitted = True
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        out = self.iforest.predict(df.reset_index(drop=True))
        f = self.forecaster.predict(out)
        out["forecast_error"], out["forecast_flag"] = f["forecast_error"], f["forecast_flag"]
        out["is_anomaly_if"] = out["is_anomaly"]
        out["is_anomaly"] = ((out["is_anomaly_if"] == 1) | (out["forecast_flag"] == 1)).astype(int)
        out["detector"] = np.select(
            [(out.is_anomaly_if == 1) & (out.forecast_flag == 1), out.is_anomaly_if == 1, out.forecast_flag == 1],
            ["BOTH", "ISOLATION_FOREST", "FORECASTER"], "-")
        return out
