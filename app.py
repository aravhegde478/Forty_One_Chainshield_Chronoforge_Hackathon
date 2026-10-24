import json
import os
import datetime
import chain
import networkx as nx
import plotly.graph_objects as go
import requests
import streamlit as st

import blockchain
import report as report_lib
from service import analyze_address

st.set_page_config(page_title="ChainShield | Wallet Risk Intelligence",
                   page_icon="🛡️", layout="wide")

# =====================================================================
# DEMO DATA (used in "Demo scenarios" mode and as an offline fallback)
# =====================================================================
SCENARIOS = {
    "High risk: phishing-linked wallet": {
        "address": "0x7a3f91c2d4e85b06a1f3c9e2b7d48a05c6e1f9b3",
        "score": 100,
        "rating": "High",
        "findings": [
            {"id": "Sanctioned address contact", "severity": "high", "points": 70,
             "reason": "Direct transfer with an address on a sanctions list.",
             "evidence": ["0xa91c...e402", "0x33bd...7f10"]},
            {"id": "Known malicious contact", "severity": "high", "points": 60,
             "reason": "Received tokens from an address flagged for phishing.",
             "evidence": ["0x5e07...19ac"]},
            {"id": "Mixer exposure", "severity": "medium", "points": 40,
             "reason": "Funds moved to or from a mixing service.",
             "evidence": ["0xc4d2...88b1"]},
            {"id": "Rapid pass-through", "severity": "medium", "points": 25,
             "reason": "Incoming funds were forwarded within 4 minutes.",
             "evidence": ["0x19ee...a360", "0x8b71...0d42"]},
        ],
        "recommendations": [
            "Do not send funds or sign approvals involving this address.",
            "If you already interacted, revoke token approvals immediately.",
            "Report the address to the relevant exchange or scam database.",
        ],
        "transactions": [
            {"Time": "2026-10-21 09:14", "Hash": "0xa91c...e402", "From": "0x9f2e...41cd", "To": "0x7a3f...f9b3", "Value (ETH)": 12.40, "Flag": "Sanctioned"},
            {"Time": "2026-10-21 09:18", "Hash": "0x19ee...a360", "From": "0x7a3f...f9b3", "To": "0xc7a1...3b90", "Value (ETH)": 12.35, "Flag": "Pass-through"},
            {"Time": "2026-10-20 22:03", "Hash": "0x5e07...19ac", "From": "0xbad0...0001", "To": "0x7a3f...f9b3", "Value (ETH)": 0.80, "Flag": "Malicious"},
            {"Time": "2026-10-19 15:47", "Hash": "0xc4d2...88b1", "From": "0x7a3f...f9b3", "To": "0xaaa0...0001", "Value (ETH)": 3.00, "Flag": "Mixer"},
            {"Time": "2026-10-18 11:20", "Hash": "0x2d8f...6e55", "From": "0x41b8...92de", "To": "0x7a3f...f9b3", "Value (ETH)": 0.05, "Flag": "-"},
        ],
        "nodes": [
            {"id": "target", "label": "0x7a3f...f9b3", "type": "target"},
            {"id": "n1", "label": "0x9f2e...41cd", "type": "malicious"},
            {"id": "n2", "label": "0xbad0...0001", "type": "malicious"},
            {"id": "n3", "label": "0xaaa0...0001", "type": "mixer"},
            {"id": "n4", "label": "0xc7a1...3b90", "type": "normal"},
            {"id": "n5", "label": "0x41b8...92de", "type": "normal"},
        ],
        "edges": [("n1", "target"), ("n2", "target"), ("target", "n3"), ("target", "n4"), ("n5", "target")],
    },
    "Medium risk: mixer exposure": {
        "address": "0x3b9d05e1a7c248f6d0b3e91a45c7f28d6e0a1c74",
        "score": 55,
        "rating": "Medium",
        "findings": [
            {"id": "Mixer exposure", "severity": "medium", "points": 40,
             "reason": "Funds moved to or from a mixing service.",
             "evidence": ["0x71aa...c3e9"]},
            {"id": "New wallet burst", "severity": "low", "points": 15,
             "reason": "14 transactions within 2 hours of wallet creation.",
             "evidence": ["0xd2e0...5b18", "0x44fc...a0d7"]},
        ],
        "recommendations": [
            "Treat with caution and verify the owner before large transfers.",
            "Check whether the mixer contact was a one-off or repeated.",
        ],
        "transactions": [
            {"Time": "2026-10-22 18:40", "Hash": "0x71aa...c3e9", "From": "0x3b9d...1c74", "To": "0xaaa0...0001", "Value (ETH)": 1.50, "Flag": "Mixer"},
            {"Time": "2026-10-22 16:12", "Hash": "0xd2e0...5b18", "From": "0x88c1...f203", "To": "0x3b9d...1c74", "Value (ETH)": 0.30, "Flag": "Burst"},
            {"Time": "2026-10-22 16:05", "Hash": "0x44fc...a0d7", "From": "0x5a90...7e12", "To": "0x3b9d...1c74", "Value (ETH)": 0.10, "Flag": "Burst"},
        ],
        "nodes": [
            {"id": "target", "label": "0x3b9d...1c74", "type": "target"},
            {"id": "n1", "label": "0xaaa0...0001", "type": "mixer"},
            {"id": "n2", "label": "0x88c1...f203", "type": "normal"},
            {"id": "n3", "label": "0x5a90...7e12", "type": "normal"},
        ],
        "edges": [("target", "n1"), ("n2", "target"), ("n3", "target")],
    },
    "Low risk: normal wallet": {
        "address": "0x52e8c0a9b1d6473f8e2a05c9d1b7f4a3e6c08d19",
        "score": 8,
        "rating": "Low",
        "findings": [],
        "recommendations": [
            "No risk indicators found. Always double-check addresses before signing.",
        ],
        "transactions": [
            {"Time": "2026-10-22 10:02", "Hash": "0xe1b4...90aa", "From": "0x52e8...8d19", "To": "0x6c3d...b7e4", "Value (ETH)": 0.25, "Flag": "-"},
            {"Time": "2026-10-15 20:31", "Hash": "0x08fd...2c61", "From": "0x1a7e...55b0", "To": "0x52e8...8d19", "Value (ETH)": 1.10, "Flag": "-"},
        ],
        "nodes": [
            {"id": "target", "label": "0x52e8...8d19", "type": "target"},
            {"id": "n1", "label": "0x6c3d...b7e4", "type": "normal"},
            {"id": "n2", "label": "0x1a7e...55b0", "type": "normal"},
        ],
        "edges": [("target", "n1"), ("n2", "target")],
    },
}
LOOKUP = {v["address"].lower(): v for v in SCENARIOS.values()}

# ---------- palette ----------
GREEN = "#4ade80"
LIGHT = "#86efac"
MUTED = "#7d8f84"
BORDER = "#16241b"
RATING_COLOR = {"High": "#f87171", "Medium": "#fbbf24", "Low": "#4ade80",
                "Insufficient data": "#7d8f84"}
SEV_COLOR = {"high": "#f87171", "medium": "#fbbf24", "low": "#7dd3fc"}
NODE_COLOR = {"target": "#86efac", "malicious": "#f87171", "mixer": "#fbbf24", "normal": "#3f5247"}
FLAG_COLOR = {"Sanctioned": "#f87171", "Malicious": "#f87171", "Mixer": "#fbbf24",
              "Pass-through": "#fbbf24", "Burst": "#7dd3fc"}

# ---------- global styling ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"], .stApp {font-family: 'Inter', sans-serif;}
.stApp {background: radial-gradient(1200px 500px at 85% -10%, #0c1f15 0%, #050806 55%);}
#MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"] {display: none !important;}
[data-testid="stHeader"] {background: transparent;}
.block-container {padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1280px;}

/* sidebar */
[data-testid="stSidebar"] {background: #030504; border-right: 1px solid #12201a;}
[data-testid="stSidebar"] .block-container {padding-top: 1.5rem;}

/* top bar */
.topbar {display:flex; align-items:center; justify-content:space-between;
         padding: 12px 18px; border:1px solid #16241b; border-radius:14px;
         background: linear-gradient(90deg, #08110c, #0a1610); margin-bottom: 18px;}
.logo {display:flex; align-items:center; gap:12px;}
.logo-mark {width:36px; height:36px; border-radius:9px; display:flex; align-items:center;
            justify-content:center; font-weight:800; color:#03110a; font-size:.95rem;
            background: linear-gradient(135deg, #86efac, #22c55e);
            box-shadow: 0 0 18px #4ade8055;}
.logo-text {font-size:1.25rem; font-weight:800; letter-spacing:.3px; color:#f1f8f4;}
.logo-text span {color:#86efac;}
.logo-sub {font-size:.72rem; color:#7d8f84; letter-spacing:1.2px; text-transform:uppercase;}
.status {display:flex; gap:10px; align-items:center;}
.pill {display:inline-flex; align-items:center; gap:7px; padding:5px 12px; border-radius:999px;
       font-size:.72rem; font-weight:600; letter-spacing:.4px; border:1px solid #1d3326;
       background:#0a1610; color:#a7f3d0;}
.dot {width:7px; height:7px; border-radius:50%; background:#4ade80; box-shadow:0 0 8px #4ade80;}

/* section titles */
.section-title {font-size:.72rem; font-weight:700; letter-spacing:1.6px; color:#7d8f84;
                text-transform:uppercase; margin: 6px 0 10px 2px;}
.page-title {font-size:1.7rem; font-weight:800; color:#f1f8f4; margin:0;}
.page-sub {color:#7d8f84; font-size:.9rem; margin: 2px 0 14px 0;}

/* cards */
div[class*="st-key-card"] {background:#0a100c; border:1px solid #16241b; border-radius:14px;
                           padding:16px 18px;}
.kpi {background:#0a100c; border:1px solid #16241b; border-radius:14px; padding:16px 18px;
      position:relative; overflow:hidden; height:100%;}
.kpi:before {content:""; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--c);}
.kpi-label {font-size:.7rem; font-weight:700; letter-spacing:1.4px; color:#7d8f84; text-transform:uppercase;}
.kpi-value {font-size:2.1rem; font-weight:800; line-height:1.15; margin-top:6px; color:var(--c);}
.kpi-sub {font-size:.78rem; color:#7d8f84; margin-top:2px;}

/* verdict */
.verdict {border-radius:14px; padding:18px 22px; margin-bottom:16px; border:1px solid;
          display:flex; align-items:center; justify-content:space-between; gap:16px;}
.verdict-title {font-size:1.35rem; font-weight:800; color:#f1f8f4; margin-left:12px;}
.addr {font-family:'JetBrains Mono', monospace; font-size:.82rem; color:#a8bbb0; margin-top:8px;
       word-break:break-all;}
.badge {display:inline-block; padding:3px 11px; border-radius:999px; font-size:.7rem;
        font-weight:700; letter-spacing:.6px; text-transform:uppercase;}

/* findings */
.finding {background:#0a100c; border:1px solid #16241b; border-left:4px solid; border-radius:12px;
          padding:15px 18px; margin-bottom:12px;}
.finding-head {display:flex; justify-content:space-between; align-items:center;}
.finding-title {font-weight:700; font-size:1rem; color:#f1f8f4;}
.finding-pts {font-weight:800; font-size:1.05rem; color:#f1f8f4;}
.finding-reason {color:#a8bbb0; margin:7px 0 10px 0; font-size:.92rem;}
.ev-label {font-size:.65rem; letter-spacing:1.4px; color:#7d8f84; font-weight:700;}
.chip {display:inline-block; background:#050806; border:1px solid #1d3326; border-radius:6px;
       padding:2px 9px; margin:4px 6px 0 0; font-family:'JetBrains Mono', monospace;
       font-size:.74rem; color:#86efac;}
.rec {background:#0a1610; border:1px solid #17402a; border-radius:10px; padding:11px 15px;
      margin-bottom:9px; color:#c9f5da; font-size:.92rem;}
.rec b {color:#86efac;}

/* table */
.tx-wrap {border:1px solid #16241b; border-radius:12px; overflow:auto; max-height:520px;}
table.tx {width:100%; border-collapse:collapse; font-size:.85rem;}
table.tx th {text-align:left; padding:11px 14px; background:#0c1710; color:#7d8f84;
             font-size:.68rem; letter-spacing:1.3px; text-transform:uppercase; font-weight:700;
             position:sticky; top:0;}
table.tx td {padding:11px 14px; border-top:1px solid #12201a; color:#d6e4dc;}
table.tx tr:hover td {background:#0c1710;}
table.tx td.mono {font-family:'JetBrains Mono', monospace; font-size:.8rem; color:#a8bbb0;}

/* tabs */
.stTabs [data-baseweb="tab-list"] {gap:4px; border-bottom:1px solid #16241b;}
.stTabs [data-baseweb="tab"] {color:#7d8f84; font-weight:600; padding:10px 18px; background:transparent;}
.stTabs [aria-selected="true"] {color:#86efac !important;}
.stTabs [data-baseweb="tab-highlight"] {background-color:#4ade80 !important; height:2px;}

/* inputs and buttons */
.stTextInput input {background:#050806 !important; border:1px solid #1d3326 !important;
                    color:#e8f1ec !important; font-family:'JetBrains Mono', monospace !important;
                    border-radius:10px !important; padding:12px 14px !important;}
.stTextInput input:focus {border-color:#4ade80 !important; box-shadow:0 0 0 1px #4ade8066 !important;}
.stSelectbox [data-baseweb="select"] > div {background:#0a100c; border:1px solid #1d3326; border-radius:10px;}
button[kind="primary"], [data-testid="stBaseButton-primary"] {
    background: linear-gradient(135deg, #86efac, #22c55e) !important; color:#03110a !important;
    border:none !important; font-weight:700 !important; border-radius:10px !important; padding:.55rem 1rem !important;}
button[kind="primary"]:hover, [data-testid="stBaseButton-primary"]:hover {box-shadow:0 0 18px #4ade8066;}
button[kind="secondary"], [data-testid="stBaseButton-secondary"] {
    background:#0a100c !important; color:#c9f5da !important; border:1px solid #1d3326 !important;
    border-radius:10px !important; font-weight:600 !important;}
.stDownloadButton button {background:#0a1610 !important; color:#86efac !important;
    border:1px solid #1d5a38 !important; border-radius:10px !important; font-weight:600 !important;}
hr {border-color:#12201a;}
.footer {text-align:center; color:#5d6f64; font-size:.75rem; margin-top:30px; padding-top:16px;
         border-top:1px solid #12201a;}

/* text input + select wrappers */
div[data-baseweb="input"] {background:#050806 !important; border:1px solid #1d3326 !important;
                           border-radius:10px !important;}
div[data-baseweb="input"] > div {background:transparent !important;}
div[data-baseweb="input"]:focus-within {border-color:#4ade80 !important;
                                        box-shadow:0 0 0 1px #4ade8066 !important;}
div[data-baseweb="select"] > div {background:#0a100c !important; border:1px solid #1d3326 !important;
                                  border-radius:10px !important; color:#e8f1ec !important;}
div[data-baseweb="select"] span, div[data-baseweb="select"] svg {color:#e8f1ec !important; fill:#86efac !important;}
div[data-baseweb="popover"] ul, div[data-baseweb="menu"] {background:#0a100c !important;}
div[data-baseweb="popover"] li {color:#e8f1ec !important;}
div[data-baseweb="popover"] li:hover {background:#12201a !important;}

/* tab labels */
.stTabs [data-baseweb="tab"] p {color:#9db0a5 !important; font-weight:600 !important;}
.stTabs [aria-selected="true"] p {color:#86efac !important;}

/* sidebar radio */
[data-testid="stRadio"] label p {color:#c9d8cf !important; font-weight:600;}
</style>
""", unsafe_allow_html=True)


# ---------- helpers ----------
def badge(text, color):
    return (f'<span class="badge" style="background:{color}1f;color:{color};'
            f'border:1px solid {color}55">{text}</span>')


def kpi(label, value, sub, color):
    return (f'<div class="kpi" style="--c:{color}"><div class="kpi-label">{label}</div>'
            f'<div class="kpi-value">{value}</div><div class="kpi-sub">{sub}</div></div>')


def notice(badge_text, title, text, c="#7d8f84"):
    st.markdown(
        f'<div class="verdict" style="background:#0a100c;border-color:{c}66">'
        f'<div><div style="display:flex;align-items:center">{badge(badge_text, c)}'
        f'<span class="verdict-title">{title}</span></div>'
        f'<div class="kpi-sub" style="margin-top:8px">{text}</div></div></div>',
        unsafe_allow_html=True)


API_URL = os.getenv("CHAINSHIELD_API_URL", "http://127.0.0.1:8000")


@st.cache_data(ttl=10, show_spinner=False)
def api_online() -> bool:
    try:
        return requests.get(f"{API_URL}/health", timeout=1).ok
    except requests.RequestException:
        return False


@st.cache_data(ttl=300, show_spinner=False)
def run_live(address: str) -> dict:
    try:
        resp = requests.post(f"{API_URL}/analyze", json={"address": address}, timeout=60)
    except requests.exceptions.ConnectionError:
        return analyze_address(address)       # API not running: use the engine directly
    if resp.status_code == 200:
        return resp.json()
    try:
        detail = resp.json().get("detail", "Analysis failed.")
    except ValueError:
        detail = "Analysis failed."
    raise blockchain.BlockchainError(str(detail))

def _post(path, payload):
    resp = requests.post(f"{API_URL}{path}", json=payload, timeout=180)
    if resp.status_code == 200:
        return resp.json()
    try:
        detail = resp.json().get("detail", "Request failed.")
    except ValueError:
        detail = "Request failed."
    raise chain.ChainError(str(detail))


def anchor_report(rep: dict) -> dict:
    try:
        return _post("/anchor", {"report": rep})
    except requests.exceptions.ConnectionError:       # API offline: do it locally
        h = report_lib.hash_report(rep)
        return {"report_hash": h, **chain.anchor_hash(h)}


def verify_report_onchain(rep: dict) -> dict:
    try:
        return _post("/verify", {"report": rep, "check_onchain": True})
    except requests.exceptions.ConnectionError:
        h = report_lib.hash_report(rep)
        try:
            rec = chain.get_anchor(h)
            return {"computed_hash": h,
                    "onchain": {"checked": True, "anchored": rec is not None, **(rec or {})}}
        except chain.ChainError as e:
            return {"computed_hash": h, "onchain": {"checked": False, "error": str(e)}}


def show_verification(vres: dict):
    oc = vres.get("onchain", {})
    if not oc.get("checked"):
        notice("Unavailable", "Could not check the blockchain", oc.get("error", "Unknown error."), "#fbbf24")
    elif oc.get("anchored"):
        when = datetime.datetime.fromtimestamp(oc["timestamp"]).strftime("%d %b %Y %H:%M")
        st.markdown(f'<div class="rec"><b>✓ Verified</b> &nbsp;This exact report was anchored on '
                    f'{oc.get("network", "the test network")} on {when}.</div>', unsafe_allow_html=True)
    else:
        notice("Not verified", "No matching on-chain record",
               "This report was never anchored, or it was changed after it was anchored.", "#f87171")


def gauge(score, color):
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={"font": {"size": 56, "color": color, "family": "Inter"}},
        gauge={"axis": {"range": [0, 100], "tickvals": [0, 40, 70, 100],
                        "tickcolor": "#3f5247", "tickfont": {"color": "#7d8f84", "size": 10}},
               "bar": {"color": color, "thickness": 0.26},
               "bgcolor": "#050806", "borderwidth": 0,
               "steps": [{"range": [0, 40], "color": "#0d2318"},
                         {"range": [40, 70], "color": "#2a2210"},
                         {"range": [70, 100], "color": "#2d1515"}]}))
    fig.update_layout(height=200, margin=dict(l=25, r=25, t=10, b=0),
                      paper_bgcolor="rgba(0,0,0,0)", font={"color": "#e8f1ec"})
    return fig


def breakdown_chart(findings):
    f = sorted(findings, key=lambda x: x["points"])
    fig = go.Figure(go.Bar(
        x=[x["points"] for x in f], y=[x["id"] for x in f], orientation="h",
        marker=dict(color=[SEV_COLOR[x["severity"]] for x in f]),
        text=[f'+{x["points"]}' for x in f], textposition="outside",
        textfont=dict(color="#e8f1ec"), hoverinfo="skip"))
    fig.update_layout(height=max(180, 60 * len(f) + 40), margin=dict(l=10, r=40, t=10, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      xaxis=dict(visible=False, range=[0, max(x["points"] for x in f) * 1.25]),
                      yaxis=dict(tickfont=dict(color="#c9d8cf", size=12)), bargap=0.45)
    return fig


def graph_figure(nodes, edges):
    G = nx.DiGraph()
    for n in nodes:
        G.add_node(n["id"])
    G.add_edges_from([tuple(e) for e in edges])
    pos = nx.spring_layout(G, seed=7, k=1.3)

    ex, ey = [], []
    for a, b in edges:
        ex += [pos[a][0], pos[b][0], None]
        ey += [pos[a][1], pos[b][1], None]
    edge_trace = go.Scatter(x=ex, y=ey, mode="lines", hoverinfo="none",
                            line=dict(width=1.4, color="#24382c"))
    glow = go.Scatter(
        x=[pos[n["id"]][0] for n in nodes], y=[pos[n["id"]][1] for n in nodes], mode="markers",
        hoverinfo="none",
        marker=dict(size=[58 if n["type"] == "target" else 40 for n in nodes],
                    color=[NODE_COLOR[n["type"]] for n in nodes], opacity=0.14))
    node_trace = go.Scatter(
        x=[pos[n["id"]][0] for n in nodes], y=[pos[n["id"]][1] for n in nodes],
        mode="markers+text", text=[n["label"] for n in nodes], textposition="bottom center",
        textfont=dict(color="#a8bbb0", size=11, family="JetBrains Mono"),
        hovertext=[f'{n["label"]} ({n["type"]})' for n in nodes], hoverinfo="text",
        marker=dict(size=[30 if n["type"] == "target" else 20 for n in nodes],
                    color=[NODE_COLOR[n["type"]] for n in nodes],
                    line=dict(width=2, color="#050806")))
    fig = go.Figure([edge_trace, glow, node_trace])
    fig.update_layout(showlegend=False, height=470, margin=dict(l=10, r=10, t=10, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      xaxis=dict(visible=False), yaxis=dict(visible=False))
    return fig


def tx_table(rows):
    if not rows:
        return '<div class="rec">No transactions found for this address.</div>'
    cols = list(rows[0].keys())
    head = "".join(f"<th>{c}</th>" for c in cols)
    body = ""
    for r in rows:
        tds = ""
        for c in cols:
            v = r[c]
            if c == "Flag":
                tds += (f"<td>{badge(v, FLAG_COLOR[v])}</td>" if v in FLAG_COLOR
                        else '<td style="color:#5d6f64">-</td>')
            elif c in ("Hash", "From", "To", "Time"):
                tds += f'<td class="mono">{v}</td>'
            elif isinstance(v, float):
                tds += f"<td><b>{v:,.4f}</b></td>"
            else:
                tds += f"<td>{v}</td>"
        body += f"<tr>{tds}</tr>"
    return (f'<div class="tx-wrap"><table class="tx"><thead><tr>{head}</tr></thead>'
            f'<tbody>{body}</tbody></table></div>')


# ---------- sidebar ----------
with st.sidebar:
    st.markdown('<div class="section-title" style="margin-top:0">Control panel</div>', unsafe_allow_html=True)
    mode = st.radio("Data source", ["Live analysis", "Demo scenarios"], label_visibility="collapsed")
    live = mode == "Live analysis"

    scenario = list(SCENARIOS.keys())[0]
    if not live:
        st.markdown('<div class="section-title" style="margin-top:14px">Demo scenario</div>',
                    unsafe_allow_html=True)
        scenario = st.selectbox("Scenario", list(SCENARIOS.keys()), label_visibility="collapsed")

    mode_label = "Live data" if live else "Demo data"
    api_label = "Online" if api_online() else "Offline (local fallback)"
    st.markdown('<div class="section-title" style="margin-top:22px">System</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="rec" style="font-size:.8rem">'
        f'<b>Mode</b> &nbsp; {mode_label}<br>'
        f'<b>API</b> &nbsp; {api_label}<br>'
        '<b>Scoring</b> &nbsp; Rule-based, explainable<br>'
        '<b>Access</b> &nbsp; Read-only</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title" style="margin-top:22px">Risk scale</div>', unsafe_allow_html=True)
    st.markdown(
        badge("Low 0-39", RATING_COLOR["Low"]) + " " + badge("Med 40-69", RATING_COLOR["Medium"])
        + " " + badge("High 70+", RATING_COLOR["High"]), unsafe_allow_html=True)
    st.markdown('<div class="footer" style="margin-top:40px">Team Forty_One<br>Cybersecurity Track</div>',
                unsafe_allow_html=True)

default_addr = "" if live else SCENARIOS[scenario]["address"]
now = datetime.datetime.now()

# ---------- top bar ----------
st.markdown(
    '<div class="topbar"><div class="logo"><div class="logo-mark">CS</div><div>'
    '<div class="logo-text">Chain<span>Shield</span></div>'
    '<div class="logo-sub">Explainable wallet risk analysis</div></div></div>'
    '<div class="status"><span class="pill"><span class="dot"></span>Analysis engine online</span>'
    f'<span class="pill">{now.strftime("%d %b %Y")}</span></div></div>', unsafe_allow_html=True)

# ---------- search ----------
st.markdown('<div class="page-title">Wallet Risk Analysis</div>', unsafe_allow_html=True)
st.markdown('<div class="page-sub">Enter a wallet, transaction hash, or contract address to get a risk '
            'rating, the evidence behind it, and its network of connections.</div>', unsafe_allow_html=True)

sc1, sc2 = st.columns([6, 1.2])
query = sc1.text_input("Address", value=default_addr, label_visibility="collapsed",
                       placeholder="0x... wallet address")
sc2.button("Analyze", type="primary", use_container_width=True)

st.write("")

# ---------- resolve the query ----------
q = query.strip()

if not q:
    st.markdown('<div class="section-title">How it works</div>', unsafe_allow_html=True)
    w = st.columns(4)
    steps = [("Step 1", "Input", "Wallet, transaction or contract address"),
             ("Step 2", "Threat analysis", "Patterns, threat intel, contract signals"),
             ("Step 3", "Explainable risk", "Score, evidence and reasons"),
             ("Step 4", "Security report", "Precautions and tamper-evident record")]
    for col, (a, b, c) in zip(w, steps):
        col.markdown(kpi(a, b, c, GREEN), unsafe_allow_html=True)
    st.stop()

if live:
    if not blockchain.is_valid_address(q):
        notice("Invalid input", "That is not a valid wallet address",
               "Enter an Ethereum address: 0x followed by 40 hexadecimal characters.", "#fbbf24")
        st.stop()
    try:
        with st.spinner("Fetching on-chain data and running analysis..."):
            data = run_live(q)
    except blockchain.BlockchainError as e:
        notice("Data unavailable", "Could not fetch blockchain data", str(e), "#f87171")
        st.stop()
else:
    data = LOOKUP.get(q.lower())
    if data is None:
        notice("Insufficient data", "No analysis available for this address",
               "Demo mode only knows the sample addresses. Switch to Live analysis in the sidebar.")
        st.stop()

color = RATING_COLOR[data["rating"]]
meta = data.get("meta")
checked = datetime.datetime.fromtimestamp(meta["fetched_at"]) if meta else now

# ---------- verdict ----------
headline = {"High": "Do not transact with this address", "Medium": "Proceed with caution",
            "Low": "No major risks detected"}.get(data["rating"], "Not enough data to assess")
badge_text = data["rating"] + " risk" if data["rating"] in ("High", "Medium", "Low") else data["rating"]
st.markdown(
    f'<div class="verdict" style="background:linear-gradient(90deg,{color}18,#0a100c 70%);border-color:{color}55">'
    f'<div><div style="display:flex;align-items:center">{badge(badge_text, color)}'
    f'<span class="verdict-title">{headline}</span></div>'
    f'<div class="addr">{q}</div></div>'
    f'<div style="text-align:right"><div class="kpi-label">Evidence reviewed</div>'
    f'<div style="color:#c9d8cf;font-weight:600">{len(data["findings"])} indicators · '
    f'{len(data["transactions"])} transactions</div></div></div>', unsafe_allow_html=True)

# ---------- data-quality notes ----------
if meta:
    notes = []
    if meta["source"] == "stale-cache":
        notes.append("Live data was unavailable, so this uses cached results from "
                     + checked.strftime("%d %b %H:%M") + ".")
    if meta["truncated"]:
        notes.append("Only the latest 1,000 transactions were analyzed. Older activity is not included.")
    for n in notes:
        st.markdown(f'<div class="rec" style="border-color:#5a4a17;background:#14110a;color:#f5e3a8">'
                    f'<b style="color:#fbbf24">Note</b> &nbsp;{n}</div>', unsafe_allow_html=True)

# ---------- top row ----------
left, right = st.columns([1.1, 2])
with left:
    with st.container(key="card_gauge"):
        st.markdown('<div class="kpi-label">Risk score</div>', unsafe_allow_html=True)
        st.plotly_chart(gauge(data["score"], color), use_container_width=True)
with right:
    flagged = sum(1 for n in data["nodes"] if n["type"] in ("malicious", "mixer"))
    connected = len(data["nodes"]) - 1
    k1, k2 = st.columns(2)
    k1.markdown(kpi("Risk indicators", len(data["findings"]), "triggered by the engine", color), unsafe_allow_html=True)
    k2.markdown(kpi("Transactions analyzed", len(data["transactions"]), "in the review window", GREEN), unsafe_allow_html=True)
    st.write("")
    k3, k4 = st.columns(2)
    k3.markdown(kpi("Flagged connections", flagged, f"of {connected} connected wallets",
                    "#f87171" if flagged else GREEN), unsafe_allow_html=True)
    k4.markdown(kpi("Last checked", checked.strftime("%H:%M"), checked.strftime("%d %b %Y"), LIGHT),
                unsafe_allow_html=True)

st.write("")

# ---------- tabs ----------
t1, t2, t3, t4, t5 = st.tabs(["Overview", "Evidence", "Transactions", "Network graph", "Report"])

with t1:
    o1, o2 = st.columns([1.4, 1])
    with o1:
        with st.container(key="card_breakdown"):
            st.markdown('<div class="kpi-label">Score breakdown by indicator</div>', unsafe_allow_html=True)
            if data["findings"]:
                st.plotly_chart(breakdown_chart(data["findings"]), use_container_width=True)
            else:
                st.markdown('<div class="rec">No indicators triggered. Nothing contributed to the score.</div>',
                            unsafe_allow_html=True)
    with o2:
        st.markdown('<div class="section-title">Recommended precautions</div>', unsafe_allow_html=True)
        for r in data["recommendations"]:
            st.markdown(f'<div class="rec"><b>✓</b> &nbsp;{r}</div>', unsafe_allow_html=True)

with t2:
    if not data["findings"]:
        st.markdown('<div class="rec">No risk indicators were triggered for this address.</div>',
                    unsafe_allow_html=True)
    for f in data["findings"]:
        sc = SEV_COLOR[f["severity"]]
        chips = "".join(f'<span class="chip">{h}</span>' for h in f["evidence"])
        st.markdown(
            f'<div class="finding" style="border-left-color:{sc}">'
            f'<div class="finding-head"><div><span class="finding-title">{f["id"]}</span> &nbsp;{badge(f["severity"], sc)}</div>'
            f'<span class="finding-pts">+{f["points"]}</span></div>'
            f'<div class="finding-reason">{f["reason"]}</div>'
            f'<div class="ev-label">SUPPORTING TRANSACTIONS</div>{chips}</div>', unsafe_allow_html=True)

with t3:
    st.markdown(tx_table(data["transactions"]), unsafe_allow_html=True)

with t4:
    with st.container(key="card_graph"):
        st.plotly_chart(graph_figure(data["nodes"], data["edges"]), use_container_width=True)
        st.markdown(
            badge("Target", NODE_COLOR["target"]) + " " + badge("Malicious", NODE_COLOR["malicious"]) + " "
            + badge("Mixer", NODE_COLOR["mixer"]) + " " + badge("Normal", "#7d8f84"), unsafe_allow_html=True)

with t5:
    report = report_lib.build_report(data)
    report_json = json.dumps(report, sort_keys=True, indent=2)
    report_hash = report_lib.hash_report(report)
    chain_info = chain.status()
    anchor_key = f"anchor_{report_hash}"
    verify_key = f"verify_{report_hash}"

    with st.container(key="card_report"):
        st.markdown('<div class="kpi-label">Tamper-evident security report</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="addr" style="font-size:.9rem;color:#86efac;margin:10px 0 4px 0">{report_hash}</div>'
                    '<div class="kpi-sub">SHA-256 of the report. Only this hash is anchored on-chain, never the report itself.</div>',
                    unsafe_allow_html=True)
        st.write("")
        b1, b2, b3 = st.columns(3)
        b1.download_button("Download report (JSON)", report_json, "chainshield_report.json",
                           "application/json", use_container_width=True)
        if b2.button("Anchor on-chain", disabled=not chain_info["can_anchor"], use_container_width=True,
                     help="Stores the report hash and a timestamp on the test network"):
            with st.spinner(f"Writing the hash to {chain_info['network']}..."):
                try:
                    st.session_state[anchor_key] = anchor_report(report)
                except chain.ChainError as e:
                    st.session_state[anchor_key] = {"error": str(e)}
        if b3.button("Verify on-chain", disabled=not chain_info["can_verify"], use_container_width=True,
                     help="Looks this report's hash up on the test network"):
            with st.spinner("Checking the blockchain record..."):
                st.session_state[verify_key] = verify_report_onchain(report)

    if not chain_info["can_anchor"]:
        st.markdown('<div class="rec" style="border-color:#5a4a17;background:#14110a;color:#f5e3a8">'
                    '<b style="color:#fbbf24">Note</b> &nbsp;Blockchain settings are incomplete in .env, '
                    'so anchoring or verifying is disabled.</div>', unsafe_allow_html=True)

    res = st.session_state.get(anchor_key)
    if res:
        if "error" in res:
            notice("Failed", "Could not anchor the report", res["error"], "#f87171")
        else:
            when = (datetime.datetime.fromtimestamp(res["timestamp"]).strftime("%d %b %Y %H:%M")
                    if res.get("timestamp") else "-")
            title = "Already anchored" if res.get("status") == "already_anchored" else "Anchored"
            link = (f' &nbsp;·&nbsp; <a href="{res["explorer_url"]}" target="_blank" style="color:#86efac">'
                    'View transaction</a>') if res.get("explorer_url") else ""
            tx = (f'<br><span style="font-family:monospace;font-size:.78rem;word-break:break-all">'
                  f'{res["tx_hash"]}</span>') if res.get("tx_hash") else ""
            st.markdown(f'<div class="rec"><b>✓ {title}</b> &nbsp;on {res.get("network", "")} · {when}{link}{tx}</div>',
                        unsafe_allow_html=True)

    vres = st.session_state.get(verify_key)
    if vres:
        show_verification(vres)

    with st.expander("Verify a saved report (tamper test)"):
        st.caption("Paste the contents of a downloaded report. Change any value to see verification fail.")
        pasted = st.text_area("Report JSON", height=180, key="verify_input", label_visibility="collapsed")
        if st.button("Verify pasted report", disabled=not chain_info["can_verify"]):
            try:
                parsed = json.loads(pasted)
                if not isinstance(parsed, dict):
                    raise ValueError
            except ValueError:
                notice("Invalid", "That is not a valid JSON report", "Paste the full downloaded file.", "#fbbf24")
            else:
                with st.spinner("Checking the blockchain record..."):
                    show_verification(verify_report_onchain(parsed))

    with st.expander("View report JSON"):
        st.json(report)

# ---------- footer ----------
st.markdown('<div class="footer">ChainShield · Team Forty_One · Cybersecurity Track<br>'
            'Read-only analysis of public blockchain data. Risk indicators are not proof of fraud.</div>',
            unsafe_allow_html=True)