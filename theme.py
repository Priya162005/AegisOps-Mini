"""Coffee-brown / ivory-cream look and feel: palette, CSS, small HTML helpers, Plotly styling."""
from __future__ import annotations

import streamlit as st

COFFEE, ESPRESSO, MOCHA = "#6F4E37", "#3B2A20", "#8B5E3C"
LATTE, CREAM, IVORY, SAND = "#C8A88A", "#F3E9DC", "#FFFDF5", "#E6D5BF"
ALERT = "#B3261E"
CHART_COLORS = ["#6F4E37", "#C77D3A", "#7A8B4F", "#3E7C87", "#A0522D", "#8C6A9E"]

PILL_COLORS = {  # label -> (background, text)
    "CRITICAL": (ALERT, "#FFFFFF"), "HIGH": ("#C77D3A", "#FFFFFF"), "MEDIUM": ("#D9B65D", ESPRESSO),
    "LOW": ("#7A8B4F", "#FFFFFF"),
    "OPEN": ("#3E7C87", "#FFFFFF"), "INVESTIGATING": ("#D9B65D", ESPRESSO),
    "WAITING_APPROVAL": ("#C77D3A", "#FFFFFF"), "RESOLVED": ("#5F7F4A", "#FFFFFF"), "FAILED": (ALERT, "#FFFFFF"),
    "HEALTHY": ("#5F7F4A", "#FFFFFF"), "DEGRADED": ("#C77D3A", "#FFFFFF"),
}

CSS = f"""
<style>
.stApp {{ background: {IVORY}; }}
.block-container {{ padding-top: 1.4rem; max-width: 1250px; }}
h1, h2, h3 {{ color: {ESPRESSO}; font-family: Georgia, 'Times New Roman', serif; letter-spacing: .2px; }}
h2 {{ border-bottom: 2px solid {SAND}; padding-bottom: .35rem; }}
hr {{ border-color: {SAND}; }}

/* ---------- hero banner ---------- */
.aeg-hero {{ background: linear-gradient(135deg, #3B2A20 0%, {COFFEE} 60%, {MOCHA} 100%);
  color: {IVORY}; border-radius: 16px; padding: 20px 28px; margin-bottom: 14px;
  display: flex; justify-content: space-between; align-items: center; gap: 16px;
  box-shadow: 0 4px 14px rgba(59,42,32,.25); }}
.aeg-hero h1 {{ color: {IVORY}; margin: 0; font-size: 1.9rem; border: 0; padding: 0; }}
.aeg-hero p {{ margin: 4px 0 0 0; color: {SAND}; font-size: .95rem; }}
.aeg-chip {{ background: {IVORY}; color: {ESPRESSO}; border-radius: 999px; padding: 8px 16px;
  font-weight: 600; font-size: .9rem; white-space: nowrap; }}

/* ---------- top navigation bar ---------- */
.st-key-navbar {{ background: {CREAM}; border: 1px solid {SAND}; border-radius: 14px;
  padding: 8px 10px; margin-bottom: 0; box-shadow: 0 2px 6px rgba(59,42,32,.08); }}
.st-key-navbar [data-testid="stElementContainer"], .st-key-navbar [data-testid="stButtonGroup"] {{ width: 100% !important; }}
.st-key-navbar [role="radiogroup"] {{ width: 100% !important; max-width: none !important; display: flex !important; gap: 8px; }}
.st-key-navbar button[data-variant="segmented_control"] {{ font-size: .88rem; flex: 1 1 0 !important; width: auto !important; min-width: 0 !important; max-width: none !important; justify-content: center;
  background: {IVORY}; border: 1px solid {SAND}; border-radius: 10px; padding: 10px 4px; color: {ESPRESSO};
  transition: all .15s ease; }}
.st-key-navbar button[data-variant="segmented_control"] * {{ color: inherit !important; white-space: nowrap;
  font-weight: 600; overflow: visible !important; text-overflow: clip !important; max-width: none !important; }}
.st-key-navbar button[data-variant="segmented_control"]:hover {{ background: {SAND}; }}
.st-key-navbar button[data-variant="segmented_control"][aria-checked="true"] {{ background: {COFFEE};
  color: {IVORY}; border-color: {COFFEE}; box-shadow: 0 2px 6px rgba(59,42,32,.3); }}

/* ---------- cards, metrics, buttons ---------- */
[data-testid="stMetric"] {{ background: {CREAM}; border: 1px solid {SAND}; border-left: 6px solid {COFFEE};
  border-radius: 12px; padding: 14px 18px; box-shadow: 0 1px 4px rgba(59,42,32,.08); }}
[data-testid="stMetricValue"] {{ color: {COFFEE}; font-family: Georgia, serif; }}
[data-testid="stMetricLabel"] p {{ color: {MOCHA}; font-weight: 600; }}
[data-testid="stVerticalBlockBorderWrapper"] {{ border-radius: 14px; border-color: {SAND}; background: #FFFFFFAA; }}
.stButton > button {{ border-radius: 10px; border: 1px solid {COFFEE}; color: {COFFEE}; background: {IVORY};
  font-weight: 600; transition: all .15s ease; }}
.stButton > button:hover {{ background: {COFFEE}; color: {IVORY}; border-color: {COFFEE}; transform: translateY(-1px); }}
.stButton > button[kind="primary"] {{ background: {COFFEE}; color: {IVORY}; }}
.stButton > button[kind="primary"]:hover {{ background: {ESPRESSO}; border-color: {ESPRESSO}; }}
[data-testid="stExpander"] {{ border-color: {SAND}; border-radius: 12px; background: {IVORY}; }}

[data-testid="stForm"] {{ border: 0 !important; padding: 0 !important; }}

/* ---------- login + pipeline ---------- */
.aeg-brand {{ background: linear-gradient(150deg, #3B2A20 0%, {COFFEE} 65%, {MOCHA} 100%); color: {IVORY};
  border-radius: 18px; padding: 38px 34px; min-height: 470px; box-shadow: 0 6px 20px rgba(59,42,32,.28); }}
.aeg-brand h1 {{ color: {IVORY}; border: 0; font-size: 2.3rem; margin: 0 0 6px 0; padding: 0; }}
.aeg-brand p {{ color: {SAND}; }}
.aeg-brand ul {{ list-style: none; padding: 0; margin: 22px 0 0 0; }}
.aeg-brand li {{ padding: 7px 0; border-bottom: 1px solid rgba(255,253,245,.18); font-size: .95rem; }}
.aeg-brand li b {{ color: {IVORY}; }}
.aeg-stage {{ background: {CREAM}; border: 1px solid {SAND}; border-radius: 12px; padding: 10px 12px; text-align: center; }}
.aeg-stage-t {{ font-size: .72rem; letter-spacing: .6px; text-transform: uppercase; color: {MOCHA}; font-weight: 700; }}
.aeg-stage-v {{ font-family: Georgia, serif; font-size: 1.5rem; color: {COFFEE}; font-weight: 700; }}
.aeg-stage-s {{ font-size: .72rem; color: {MOCHA}; }}

/* ---------- html helpers ---------- */
.aeg-pill {{ display: inline-block; padding: 2px 11px; border-radius: 999px; font-size: .78rem;
  font-weight: 700; letter-spacing: .3px; margin-right: 4px; }}
.aeg-card {{ background: {CREAM}; border: 1px solid {SAND}; border-top: 5px solid {COFFEE};
  border-radius: 14px; padding: 14px 16px; height: 100%; box-shadow: 0 1px 4px rgba(59,42,32,.08); }}
.aeg-card .ttl {{ margin: 0 0 8px 0; color: {ESPRESSO}; font-family: Georgia, serif; font-size: 1.2rem;
  font-weight: 700; line-height: 1.2; min-height: 1.5rem; }}
.aeg-card table {{ width: 100%; font-size: .85rem; color: {ESPRESSO}; border-collapse: collapse; margin-top: 10px; }}
.aeg-card td {{ border: 0 !important; border-bottom: 1px dashed {SAND} !important; padding: 4px 2px !important; background: transparent !important; }}
.aeg-card td:last-child {{ text-align: right; font-weight: 600; }}
.aeg-foot {{ color: {MOCHA}; font-size: .8rem; text-align: center; margin-top: 30px; }}
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def pill(text: str) -> str:
    bg, fg = PILL_COLORS.get(text, (COFFEE, IVORY))
    return f'<span class="aeg-pill" style="background:{bg};color:{fg}">{text.replace("_", " ")}</span>'


def hero(title: str, subtitle: str, *chips: str) -> None:
    chip_html = "".join(f'<div class="aeg-chip">{c}</div>' for c in chips)
    st.markdown(f'<div class="aeg-hero"><div><h1>{title}</h1><p>{subtitle}</p></div>'
                f'<div style="display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end">{chip_html}</div></div>',
                unsafe_allow_html=True)


def stage(label: str, value: str, sub: str = "") -> str:
    return (f'<div class="aeg-stage"><div class="aeg-stage-t">{label}</div><div class="aeg-stage-v">{value}</div>'
            f'<div class="aeg-stage-s">{sub}</div></div>')


def service_card(name: str, health: str, rows: list[tuple[str, str]], fault: str) -> str:
    body = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in rows)
    return (f'<div class="aeg-card"><div class="ttl">{name}</div>{pill(health)}'
            f'<table>{body}</table>'
            f'<div style="margin-top:6px;font-size:.78rem;color:{MOCHA}">Active fault: {fault}</div></div>')


def style_fig(fig, height: int = 320):
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=44, b=10), colorway=CHART_COLORS,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="#FBF6EC",
        font=dict(color=ESPRESSO), title_font=dict(family="Georgia, serif", size=16, color=ESPRESSO),
        legend_title_text="", legend=dict(orientation="h", y=-0.18))
    fig.update_xaxes(gridcolor=SAND, linecolor=SAND, title_text=None)
    fig.update_yaxes(gridcolor=SAND, linecolor=SAND)
    return fig
