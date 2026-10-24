"""AegisOps web application (Streamlit).  Run with:  python -m streamlit run app.py"""
import streamlit as st

import theme
from workflow import AegisOps

st.set_page_config(page_title="AegisOps", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
theme.inject_css()

if "ops" not in st.session_state:
    st.session_state.ops = AegisOps("aegisops.db")

from views import admin, audit, dashboard, detection, incidents, login, remediation, simulation, telemetry  # noqa: E402
from views.common import allowed, ops, show_flash, system_health, user  # noqa: E402

# ------------------------------------------------------------------ login gate
if "user" not in st.session_state:
    login.render()
    st.stop()

# ------------------------------------------------------------------ navigation model (role based)
NAV = {  # label -> (icon, view)
    "Dashboard": (":material/dashboard:", dashboard.render),
    "Telemetry": (":material/monitoring:", telemetry.render),
    "Detection": (":material/radar:", detection.render),
    "Incidents": (":material/search_check:", incidents.render),
    "Remediation": (":material/build:", remediation.render),
    "Audit Log": (":material/receipt_long:", audit.render),
    "Simulation": (":material/science:", simulation.render),
}
if allowed("admin"):
    NAV["Admin"] = (":material/admin_panel_settings:", admin.render)

if st.session_state.get("nav") not in NAV:
    st.session_state["nav"] = "Dashboard"

# ------------------------------------------------------------------ header + top navigation bar
u = user()
health = system_health()
dot = {"HEALTHY": "🟢", "DEGRADED": "🟠", "CRITICAL": "🔴"}[health]
theme.hero("🛡️ AegisOps", "Agentic AI for intelligent IT operations and anomaly resolution",
           f"{dot} System {health.title()}", f"👤 {u['full_name'] or u['username']} · {u['role']}")
nav_col, out_col = st.columns([10, 1], vertical_alignment="center")
with nav_col:
    with st.container(key="navbar"):
        page = st.segmented_control("Navigate", list(NAV), required=True, key="nav",
                                    format_func=lambda p: f"{NAV[p][0]} {p}", label_visibility="collapsed")
with out_col:
    if st.button("Sign out", key="signout", width="stretch"):
        ops().db.log_event(u["username"], "LOGOUT", "Signed out")
        for k in ("user", "nav", "flash"):
            st.session_state.pop(k, None)
        st.rerun()

show_flash()
NAV[page][1]()
st.markdown('<div class="aeg-foot">AegisOps mini-project · all remediation is simulated · no real infrastructure is touched</div>',
            unsafe_allow_html=True)
