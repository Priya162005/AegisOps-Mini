# AegisOps – Agentic AI for IT Operations (web application)

A complete, working web application: sign in, watch simulated services, let the agents detect and diagnose faults,
approve safe runbooks, verify recovery, and review every decision in the audit log.
Everything runs locally, free, with no LLM and no cloud. **All remediation is simulated** – no real system is touched.

## Run it (Windows)

```bat
cd AegisOps-Mini
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m streamlit run app.py
```
Open **http://localhost:8501** and keep the terminal open. (If `streamlit` is "not recognized", always use `python -m streamlit`.)

## Sign in (demo accounts)

| Username | Password | Role | Can do |
|---|---|---|---|
| `admin` | `Admin@123` | admin | everything, plus the **Admin** module (users, policy, change freeze) |
| `operator` | `Operator@123` | operator | inject faults, run detection, investigate, **approve / reject**, verify |
| `viewer` | `Viewer@123` | viewer | read-only (all action buttons are disabled) |

Passwords are stored as salted PBKDF2-SHA256 hashes; 5 failed logins lock an account (an admin can unlock it).

## Modules (top navigation bar)

| Module | What it is (system-design box) | What you can do |
|---|---|---|
| **Dashboard** | Orchestrator | KPIs, agent pipeline counters, **Run orchestrator cycle**, service health, pending approvals |
| **Telemetry** | Telemetry store | Metric charts, searchable log stream (data persisted in SQLite) |
| **Detection** | Detection Agent | Isolation Forest + neural forecaster (hybrid), anomaly scores, flagged minutes, evaluation of all three detectors |
| **Incidents** | Diagnosis Agent | Ranked root-cause hypotheses, evidence, read-only tool-call trace, runbook, incident timeline |
| **Remediation** | Policy engine + Action Agent | Approval queue with policy pre-check, verification, runbook library, action history |
| **Audit Log** | Audit Agent | Filterable, append-only record of every event; CSV download |
| **Simulation** | Monitored services | Inject: CPU spike, memory leak, DB connection failure, network latency, application error spike |
| **Admin** | (admin only) | Create users, roles, lock/unlock, reset passwords, **change freeze**, risk-policy table |

## Demo in 2 minutes
1. Sign in as `operator`. **Simulation** → click **CPU spike**.
2. **Dashboard** → **Run orchestrator cycle** (detects, creates the incident, runs the Diagnosis Agent).
3. **Incidents** → read the ranked hypotheses, evidence and tool calls.
4. **Remediation** → review the policy pre-check → **Approve & execute** → **Verification** tab → **Verify recovery** → RESOLVED.
5. **Audit Log** → see every step. Try **Reject** on another fault, or sign in as `admin` and turn on **Change freeze**.

## How the safety policy works
LOW risk runs automatically · MEDIUM needs a human approval · HIGH or unknown actions never run · a change freeze blocks
everything · if verification fails the simulated state is rolled back and the incident is escalated (FAILED).

## The model (measured, held-out synthetic data)
Row level: Isolation Forest P 0.952 / R 0.986 / F1 0.968 / FPR 0.005; forecaster F1 ≈ 0.83; hybrid recall 0.993.
Event level: 7 of 7 injected faults produced an incident with 0 false incidents. Open **Detection** to see all numbers computed live.
Limitations: synthetic data; the forecaster is a small MLP (not an LSTM) and echoes faults for a few minutes after they end;
the Isolation Forest needs `contamination` close to the real anomaly rate.

## Files
`app.py` (entry, login gate, navigation) · `views/` (one file per module) · `workflow.py` (orchestrator) ·
`anomaly_detector.py` · `agent.py` (diagnosis, policy, runbooks) · `remediation.py` · `database.py` (SQLite) ·
`auth.py` · `data_generator.py` · `theme.py` + `.streamlit/config.toml` (coffee/ivory theme) · `tests/` (94 tests: `python -m pytest -q`).
