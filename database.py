"""SQLite persistence (built-in sqlite3, no ORM)."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Optional

import pandas as pd

import auth

STATUSES = ["OPEN", "INVESTIGATING", "WAITING_APPROVAL", "RESOLVED", "FAILED"]
ACTIVE_STATUSES = ["OPEN", "INVESTIGATING", "WAITING_APPROVAL"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL, anomaly_type TEXT NOT NULL, severity TEXT NOT NULL,
    timestamp TEXT NOT NULL, metric_evidence TEXT NOT NULL, log_messages TEXT NOT NULL,
    root_cause TEXT, recommended_action TEXT, risk_level TEXT,
    status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER, service TEXT NOT NULL,
    start_ts TEXT NOT NULL, end_ts TEXT NOT NULL, n_flagged INTEGER, max_score REAL,
    detected_at TEXT NOT NULL, UNIQUE(service, start_ts));
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
    result TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, action TEXT NOT NULL,
    decision TEXT NOT NULL, decided_by TEXT, reason TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, action TEXT NOT NULL,
    executed INTEGER NOT NULL, message TEXT, before_state TEXT, after_state TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, full_name TEXT,
    role TEXT NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, last_login TEXT);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, actor TEXT NOT NULL,
    event_type TEXT NOT NULL, incident_id TEXT, service TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS services (
    service_id INTEGER PRIMARY KEY AUTOINCREMENT, service_name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS metrics (
    metric_id INTEGER PRIMARY KEY AUTOINCREMENT, service_id INTEGER NOT NULL, timestamp TEXT NOT NULL,
    cpu REAL, memory REAL, disk REAL, latency_ms REAL, request_count INTEGER, error_rate REAL,
    log_message TEXT, anomaly_label INTEGER, anomaly_type TEXT, UNIQUE(service_id, timestamp));
CREATE TABLE IF NOT EXISTS verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, passed INTEGER NOT NULL,
    checks TEXT NOT NULL, created_at TEXT NOT NULL);
"""

JSON_FIELDS = ("metric_evidence", "log_messages")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def incident_label(row_id: int) -> str:
    return f"INC-{row_id:04d}"


def parse_incident_id(label: str) -> int:
    return int(label.split("-")[1])


class Database:
    def __init__(self, path: str = "aegisops.db"):
        self.path = path
        with self._conn() as c:
            c.executescript(SCHEMA)
        if not self._all("SELECT 1 FROM users LIMIT 1"):
            for username, password, role, full_name in auth.DEFAULT_USERS:
                self.add_user(username, password, role, full_name)

    @contextmanager
    def _conn(self):
        """Commit on success, roll back on error, and always close (avoids file locks on Windows)."""
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _all(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    # ---- incidents
    def create_incident(self, service: str, severity: str, timestamp: str,
                        metric_evidence: dict, log_messages: list[str],
                        anomaly_type: str = "UNCLASSIFIED") -> str:
        now = _now()
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO incidents (service, anomaly_type, severity, timestamp, metric_evidence,"
                " log_messages, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (service, anomaly_type, severity, timestamp, json.dumps(metric_evidence),
                 json.dumps(log_messages), "OPEN", now, now))
            return incident_label(cur.lastrowid)

    def get_incident(self, label: str) -> Optional[dict]:
        rows = self._all("SELECT * FROM incidents WHERE id=?", (parse_incident_id(label),))
        return self._decode(rows[0]) if rows else None

    def list_incidents(self, status: Optional[str] = None) -> list[dict]:
        sql, args = "SELECT * FROM incidents", ()
        if status:
            sql, args = sql + " WHERE status=?", (status,)
        return [self._decode(r) for r in self._all(sql + " ORDER BY id DESC", args)]

    def update_incident(self, label: str, **fields: Any) -> None:
        allowed = {"anomaly_type", "severity", "root_cause", "recommended_action", "risk_level", "status"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"Cannot update fields: {bad}")
        if fields.get("status") and fields["status"] not in STATUSES:
            raise ValueError(f"Invalid status: {fields['status']}")
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._conn() as c:
            c.execute(f"UPDATE incidents SET {cols}, updated_at=? WHERE id=?",
                      (*fields.values(), _now(), parse_incident_id(label)))

    def _decode(self, row: dict) -> dict:
        for f in JSON_FIELDS:
            row[f] = json.loads(row[f])
        row["incident_id"] = incident_label(row["id"])
        return row

    # ---- detections
    def record_detection(self, service: str, start_ts: str, end_ts: str, n_flagged: int,
                         max_score: float, incident_id: Optional[str]) -> bool:
        """Returns False if this event was already recorded (dedupe on service+start)."""
        with self._conn() as c:
            try:
                c.execute("INSERT INTO detections (incident_id, service, start_ts, end_ts, n_flagged,"
                          " max_score, detected_at) VALUES (?,?,?,?,?,?,?)",
                          (parse_incident_id(incident_id) if incident_id else None, service, start_ts,
                           end_ts, n_flagged, max_score, _now()))
                return True
            except sqlite3.IntegrityError:
                return False

    def detection_exists(self, service: str, start_ts: str) -> bool:
        return bool(self._all("SELECT 1 FROM detections WHERE service=? AND start_ts=?", (service, start_ts)))

    def list_detections(self) -> list[dict]:
        return self._all("SELECT * FROM detections ORDER BY id DESC")

    # ---- agent / approval / remediation / verification
    def save_investigation(self, label: str, result: dict) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO investigations (incident_id, result, created_at) VALUES (?,?,?)",
                      (parse_incident_id(label), json.dumps(result), _now()))

    def record_approval(self, label: str, action: str, decision: str, decided_by: str = "operator",
                        reason: str = "") -> None:
        if decision not in ("APPROVED", "REJECTED"):
            raise ValueError("decision must be APPROVED or REJECTED")
        with self._conn() as c:
            c.execute("INSERT INTO approvals (incident_id, action, decision, decided_by, reason, created_at)"
                      " VALUES (?,?,?,?,?,?)",
                      (parse_incident_id(label), action, decision, decided_by, reason, _now()))

    def latest_approval(self, label: str, action: str) -> Optional[dict]:
        rows = self._all("SELECT * FROM approvals WHERE incident_id=? AND action=? ORDER BY id DESC LIMIT 1",
                         (parse_incident_id(label), action))
        return rows[0] if rows else None

    def record_remediation(self, label: str, result: dict) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO remediations (incident_id, action, executed, message, before_state,"
                      " after_state, created_at) VALUES (?,?,?,?,?,?,?)",
                      (parse_incident_id(label), result["action"], int(result["executed"]), result["message"],
                       json.dumps(result["before"]), json.dumps(result["after"]), _now()))

    def list_remediations(self) -> list[dict]:
        rows = self._all("SELECT * FROM remediations ORDER BY id DESC")
        for r in rows:
            r["incident"] = incident_label(r["incident_id"])
            r["before_state"], r["after_state"] = json.loads(r["before_state"]), json.loads(r["after_state"])
        return rows

    def record_verification(self, label: str, result: dict) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO verifications (incident_id, passed, checks, created_at) VALUES (?,?,?,?)",
                      (parse_incident_id(label), int(result["passed"]), json.dumps(result["checks"]), _now()))

    def related(self, label: str) -> dict:
        i = parse_incident_id(label)
        out = {}
        for table in ("investigations", "approvals", "remediations", "verifications"):
            rows = self._all(f"SELECT * FROM {table} WHERE incident_id=? ORDER BY id", (i,))
            for r in rows:
                for k in ("result", "before_state", "after_state", "checks"):
                    if k in r and r[k]:
                        r[k] = json.loads(r[k])
            out[table] = rows
        return out

    def clear(self) -> None:
        with self._conn() as c:
            for t in ("incidents", "detections", "investigations", "approvals", "remediations", "verifications"):
                c.execute(f"DELETE FROM {t}")
            c.execute("DELETE FROM sqlite_sequence WHERE name IN "
                      "('incidents','detections','investigations','approvals','remediations','verifications')")

    # ---- users / authentication
    def add_user(self, username: str, password: str, role: str, full_name: str = "") -> None:
        username = username.strip().lower()
        if not username or not username.replace("_", "").replace(".", "").isalnum():
            raise ValueError("Username must contain only letters, digits, '_' or '.'.")
        if role not in auth.ROLES:
            raise ValueError(f"Role must be one of {auth.ROLES}.")
        if len(password) < auth.MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters.")
        pw_hash, salt = auth.hash_password(password)
        try:
            with self._conn() as c:
                c.execute("INSERT INTO users (username, full_name, role, salt, password_hash, created_at)"
                          " VALUES (?,?,?,?,?,?)", (username, full_name, role, salt, pw_hash, _now()))
        except sqlite3.IntegrityError:
            raise ValueError(f"User '{username}' already exists.")

    def authenticate(self, username: str, password: str) -> tuple[Optional[dict], str]:
        """Returns (user, message). user is None on failure; 5 failures lock the account."""
        rows = self._all("SELECT * FROM users WHERE username=?", (username.strip().lower(),))
        if not rows:
            return None, "Invalid username or password."
        u = rows[0]
        if not u["active"]:
            return None, "This account is locked or disabled. Contact an administrator."
        if auth.verify_password(password, u["salt"], u["password_hash"]):
            with self._conn() as c:
                c.execute("UPDATE users SET failed_attempts=0, last_login=? WHERE id=?", (_now(), u["id"]))
            return {k: u[k] for k in ("username", "full_name", "role")}, "OK"
        fails = u["failed_attempts"] + 1
        locked = fails >= auth.MAX_FAILED_ATTEMPTS
        with self._conn() as c:
            c.execute("UPDATE users SET failed_attempts=?, active=? WHERE id=?", (fails, 0 if locked else 1, u["id"]))
        left = auth.MAX_FAILED_ATTEMPTS - fails
        return None, ("Account locked after too many failed attempts." if locked
                      else f"Invalid username or password. {left} attempt(s) left.")

    def list_users(self) -> list[dict]:
        return self._all("SELECT id, username, full_name, role, active, failed_attempts, created_at, last_login"
                         " FROM users ORDER BY id")

    def set_user_role(self, username: str, role: str) -> None:
        if role not in auth.ROLES:
            raise ValueError(f"Role must be one of {auth.ROLES}.")
        with self._conn() as c:
            c.execute("UPDATE users SET role=? WHERE username=?", (role, username))

    def set_user_active(self, username: str, active: bool) -> None:
        with self._conn() as c:
            c.execute("UPDATE users SET active=?, failed_attempts=0 WHERE username=?", (int(active), username))

    def change_password(self, username: str, new_password: str) -> None:
        if len(new_password) < auth.MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {auth.MIN_PASSWORD_LENGTH} characters.")
        pw_hash, salt = auth.hash_password(new_password)
        with self._conn() as c:
            c.execute("UPDATE users SET salt=?, password_hash=?, failed_attempts=0 WHERE username=?",
                      (salt, pw_hash, username))

    # ---- audit log (append-only)
    def log_event(self, actor: str, event_type: str, detail: str = "",
                  incident_id: Optional[str] = None, service: Optional[str] = None) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO audit_events (timestamp, actor, event_type, incident_id, service, detail)"
                      " VALUES (?,?,?,?,?,?)", (datetime.now().isoformat(timespec="seconds"), actor, event_type,
                                                incident_id, service, detail))

    def list_events(self, limit: int = 500, event_type: Optional[str] = None, actor: Optional[str] = None,
                    incident_id: Optional[str] = None, search: Optional[str] = None) -> list[dict]:
        sql, args, where = "SELECT * FROM audit_events", [], []
        for col, val in (("event_type", event_type), ("actor", actor), ("incident_id", incident_id)):
            if val:
                where.append(f"{col}=?"); args.append(val)
        if search:
            where.append("(detail LIKE ? OR service LIKE ?)"); args += [f"%{search}%"] * 2
        if where:
            sql += " WHERE " + " AND ".join(where)
        return self._all(sql + " ORDER BY id DESC LIMIT ?", tuple(args) + (limit,))

    # ---- settings
    def get_setting(self, key: str, default: str = "") -> str:
        rows = self._all("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    def set_setting(self, key: str, value: str) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (key, value))

    # ---- telemetry store (services + metrics)
    def save_metrics(self, df: pd.DataFrame) -> None:
        with self._conn() as c:
            for name in df["service"].unique():
                c.execute("INSERT OR IGNORE INTO services (service_name) VALUES (?)", (name,))
            ids = {r["service_name"]: r["service_id"] for r in c.execute("SELECT * FROM services").fetchall()}
            rows = [(ids[r.service], pd.Timestamp(r.timestamp).isoformat(), float(r.cpu), float(r.memory), float(r.disk),
                     float(r.latency_ms), int(r.request_count), float(r.error_rate), r.log_message,
                     int(r.anomaly_label), r.anomaly_type) for r in df.itertuples(index=False)]
            c.executemany("INSERT OR REPLACE INTO metrics (service_id, timestamp, cpu, memory, disk, latency_ms,"
                          " request_count, error_rate, log_message, anomaly_label, anomaly_type)"
                          " VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def load_metrics(self, max_ticks: int = 600) -> pd.DataFrame:
        rows = self._all(
            "SELECT m.timestamp, s.service_name AS service, m.cpu, m.memory, m.disk, m.latency_ms, m.request_count,"
            " m.error_rate, m.log_message, m.anomaly_label, m.anomaly_type FROM metrics m"
            " JOIN services s ON s.service_id = m.service_id WHERE m.timestamp >= ("
            " SELECT MIN(t) FROM (SELECT DISTINCT timestamp AS t FROM metrics ORDER BY t DESC LIMIT ?))"
            " ORDER BY m.timestamp, s.service_name", (max_ticks,))
        df = pd.DataFrame(rows)
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df

    def list_services(self) -> list[dict]:
        return self._all("SELECT * FROM services ORDER BY service_id")

    # ---- stats
    def stats(self) -> dict:
        incs = self.list_incidents()
        return {
            "total": len(incs),
            "active": sum(i["status"] in ACTIVE_STATUSES for i in incs),
            "resolved": sum(i["status"] == "RESOLVED" for i in incs),
            "failed": sum(i["status"] == "FAILED" for i in incs),
            "critical": sum(i["severity"] == "CRITICAL" for i in incs),
            "investigated": sum(bool(i["root_cause"]) for i in incs),
            "executed": self._all("SELECT COUNT(*) AS n FROM remediations WHERE executed=1")[0]["n"],
            "audit_events": self._all("SELECT COUNT(*) AS n FROM audit_events")[0]["n"],
            "detections": self._all("SELECT COUNT(*) AS n FROM detections")[0]["n"],
        }
