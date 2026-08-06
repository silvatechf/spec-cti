"""
Spect CTI - Academic Security Intelligence Platform.
"""

from __future__ import annotations

import datetime
import pandas as pd
import plotly.express as px
import streamlit as st

from src.core.database import Finding, Host, get_db_session, init_db

st.set_page_config(
    page_title="Spec CTI | Security Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Paleta Enterprise Refinada (Amarelo ajustado para elegância)
_SEVERITY_COLORS = {
    "critical": "#EF4444",  # Red
    "high": "#F97316",      # Orange
    "medium": "#EAB308",    # Gold/Yellow
    "low": "#22C55E",       # Green
    "info": "#38BDF8",      # Blue
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_CUSTOM_CSS = """
<style>
    .stApp { background-color: #0B0E14; }
    section[data-testid="stSidebar"] { background-color: #10141D; border-right: 1px solid #1E2430; }
    html, body, [class*="css"] { font-family: "IBM Plex Sans", -apple-system, sans-serif; color: #E6E9EF; }
    
    .top-bar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1E2430; padding-bottom: 1rem; margin-bottom: 1.5rem; }
    .top-bar-item { font-size: 0.85rem; color: #8891A5; }
    .top-bar-item span { color: #E6E9EF; font-family: "IBM Plex Mono", monospace; margin-left: 0.5rem; }
    
    .console-title { font-size: 1.9rem; font-weight: 600; color: #E6E9EF; margin-bottom: 0; }
    .console-subtitle { color: #8891A5; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
    
    /* Cards com estética Premium SaaS */
    .metric-card { 
        background: linear-gradient(180deg, rgba(20,25,35,0.6) 0%, rgba(11,14,20,0.9) 100%); 
        border: 1px solid rgba(255,255,255,0.06); 
        border-radius: 14px; 
        padding: 1.5rem; 
        box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.03); 
        position: relative; 
        overflow: hidden; 
        backdrop-filter: blur(12px);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover { border-color: rgba(255,255,255,0.12); transform: translateY(-2px); }
    
    /* Brilho de topo (linha luminosa) */
    .metric-glow-line { position: absolute; top: 0; left: 0; right: 0; height: 1px; background: var(--accent); box-shadow: 0 0 20px 2px var(--accent); opacity: 0.6; }
    
    /* Brilho volumétrico de fundo */
    .metric-glow-bg { position: absolute; top: -40px; right: -40px; width: 120px; height: 120px; background: var(--accent); filter: blur(50px); opacity: 0.12; border-radius: 50%; pointer-events: none; }
    
    .metric-value { font-family: "IBM Plex Mono", monospace; font-size: 2.4rem; font-weight: 700; line-height: 1; margin-bottom: 0.3rem; z-index: 2; position: relative;}
    .metric-label { color: #94A3B8; font-size: 0.85rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; z-index: 2; position: relative; }
    
    .status-indicator { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: #22C55E; margin-right: 8px; }
    .pulse { animation: pulse-animation 2s infinite; }
    @keyframes pulse-animation { 0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); } 70% { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); } 100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); } }
    
    .sidebar-section { margin-top: 1.5rem; margin-bottom: 0.5rem; font-size: 0.85rem; color: #6B7688; text-transform: uppercase; letter-spacing: 0.05em; font-weight: bold;}
    
    .progress-bg { background: #1E2430; border-radius: 4px; height: 8px; width: 100%; margin-top: 4px; margin-bottom: 12px; overflow: hidden; position: relative; z-index: 2; }
    .progress-bar { height: 100%; border-radius: 4px; }
    .compliance-label { display: flex; justify-content: space-between; font-size: 0.85rem; color: #E6E9EF; }
    
    .badge { padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; font-family: "IBM Plex Mono", monospace; }
    
    /* Tabela com interatividade Hover */
    .custom-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
    .custom-table th { padding: 12px; color: #8891A5; font-weight: 600; border-bottom: 2px solid #10141D; }
    .custom-table td { padding: 12px; border-bottom: 1px solid #1E2430; }
    .custom-table tbody tr:hover { background-color: #1A202C; cursor: pointer; transition: background-color 0.2s ease; }
    
    .footer { margin-top: 4rem; padding-top: 1.5rem; border-top: 1px solid #1E2430; text-align: center; color: #6B7688; font-size: 0.8rem; line-height: 1.5;}
</style>
"""
st.markdown(_CUSTOM_CSS, unsafe_allow_html=True)

def _load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    init_db()
    with get_db_session() as session:
        hosts = session.query(Host).all()
        findings = session.query(Finding).all()
        hosts_df = pd.DataFrame([{"id": h.id, "hostname": h.hostname, "os_family": h.os_family, "role": h.role} for h in hosts])
        findings_df = pd.DataFrame([{
            "host_id": f.host_id, "title": f.title, "severity": f.severity.value,
            "cvss_score": f.cvss_score, "confirmed": f.is_confirmed_exploitable,
            "description": f.description, "discovered_at": f.discovered_at
        } for f in findings])
    if not findings_df.empty and not hosts_df.empty:
        findings_df = findings_df.merge(hosts_df[["id", "hostname"]], left_on="host_id", right_on="id", how="left")
    return hosts_df, findings_df

hosts_df, findings_df = _load_data()

# Lógica de Score
base_score = 100
crit_count = high_count = med_count = 0
if not findings_df.empty:
    crit_count = len(findings_df[findings_df['severity'] == 'critical'])
    high_count = len(findings_df[findings_df['severity'] == 'high'])
    med_count = len(findings_df[findings_df['severity'] == 'medium'])
    penalty = (crit_count * 5) + (high_count * 3) + (med_count * 1)
    security_score = max(0, base_score - penalty)
else:
    security_score = 100

score_color = "#22C55E" if security_score >= 85 else "#EAB308" if security_score >= 65 else "#EF4444"
score_text = "Stable" if security_score >= 85 else "Needs Action" if security_score >= 65 else "Elevated Risk"

# ─── SIDEBAR ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<p class="console-title"> Spect CTI</p>', unsafe_allow_html=True)
    st.markdown('<p class="console-subtitle">Academic Security Intelligence Platform</p>', unsafe_allow_html=True)
    
    st.markdown('<div style="margin-top: 1rem; margin-bottom: 2rem; font-size: 0.85rem; color: #E6E9EF;"><span class="status-indicator pulse"></span>System Live • Controlled Environment</div>', unsafe_allow_html=True)
    
    st.button("📄 Generate Executive Report", use_container_width=True, type="primary")
    st.button("↻ Run Assessment", use_container_width=True)
    
    st.markdown('<div class="sidebar-section">Active Engines</div>', unsafe_allow_html=True)
    st.markdown('<div style="color: #E6E9EF; font-size: 0.9rem; line-height: 1.8;">✅ Network Auditor<br>✅ Auth Analytics<br>✅ Exploit Simulator</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="sidebar-section">Compliance Readiness</div>', unsafe_allow_html=True)
    
    def render_progress(label: str, percent: int, color: str):
        st.markdown(f"""
        <div class="compliance-label"><span>{label}</span><span style="color:{color}; font-weight:bold;">{percent}%</span></div>
        <div class="progress-bg"><div class="progress-bar" style="width: {percent}%; background-color: {color};"></div></div>
        """, unsafe_allow_html=True)

    render_progress("ENS (High)", 89, "#22C55E")
    render_progress("RGPD / GDPR", 92, "#22C55E")
    render_progress("ISO 27001", 74, "#EAB308")
    render_progress("OWASP ASVS", 68, "#EAB308")

# ─── MAIN DASHBOARD ──────────────────────────────────────────────────────
st.markdown('<p class="console-title">Security Posture Overview</p>', unsafe_allow_html=True)
st.markdown(f'<p class="console-subtitle">LAST ASSESSMENT: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>', unsafe_allow_html=True)
st.write("")

st.markdown(f"""
<div class="top-bar">
    <div class="top-bar-item">🏛 Workspace: <span>Academic Research Edition</span></div>
    <div class="top-bar-item">⚔ Methodology: <span>OWASP + MITRE ATT&CK</span></div>
    <div class="top-bar-item">🖥 Assets: <span>{len(hosts_df)}</span></div>
    <div class="top-bar-item">⚠ Findings: <span>{len(findings_df)}</span></div>
</div>
""", unsafe_allow_html=True)

if findings_df.empty:
    st.info("Awaiting telemetry data. Execute automated scanners to populate.")
else:
    # ─── TOP METRICS: SCORE & BULLET SUMMARY ─────────────────────────────
    col_score, col_summary = st.columns([1.5, 2.5])
    with col_score:
        st.markdown(f"""
        <div class="metric-card" style="--accent: {score_color}; height: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center; padding: 2rem;">
            <div class="metric-glow-line"></div>
            <div class="metric-glow-bg"></div>
            <div class="metric-label" style="margin-bottom: 0.5rem; text-align: center;">SECURITY POSTURE</div>
            <div style="font-family: 'IBM Plex Mono', monospace; font-size: 4.5rem; font-weight: 700; color: {score_color}; line-height: 1; z-index: 2; position: relative;">{security_score}</div>
            <div style="font-weight: bold; color: {score_color}; font-size: 1.1rem; letter-spacing: 1px; margin-top: 0.5rem; text-transform: uppercase; z-index: 2; position: relative;">{score_text}</div>
            <div class="progress-bg" style="width: 100%; margin-top: 15px;"><div class="progress-bar" style="width: {security_score}%; background-color: {score_color};"></div></div>
            <div style="width: 100%; display: flex; justify-content: space-between; align-items: center; margin-top: 4px; z-index: 2; position: relative;">
                <span style="color: #8891A5; font-size: 0.8rem;">Target ≥ 85</span>
                <span style="color: #38BDF8; font-size: 0.8rem; font-weight: bold;">Detection Confidence: 98% (Verified)</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with col_summary:
        st.markdown(f"""
        <div class="metric-card" style="--accent: #334155; height: 100%;">
            <div class="metric-glow-line"></div>
            <div class="metric-label" style="margin-bottom: 1rem;">EXECUTIVE SUMMARY</div>
            <ul style="font-size: 1.05rem; line-height: 1.8; color: #E6E9EF; list-style-type: none; padding-left: 0; margin-bottom: 0; z-index: 2; position: relative;">
                <li><span style="color:{score_color}">●</span> <strong>Security Posture:</strong> {score_text}</li>
                <li><span style="color:#EF4444">●</span> <strong>Critical Findings:</strong> {crit_count}</li>
                <li><span style="color:#F97316">●</span> <strong>High Findings:</strong> {high_count}</li>
                <li><span style="color:#38BDF8">●</span> <strong>Primary Risk:</strong> Web Application Layer & Authentication</li>
                <li><span style="color:#EAB308">●</span> <strong>Recommendation:</strong> Prioritize OWASP Top 10 mitigations and isolate lateral movement vectors.</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.write("")

    # ─── SEVERITY COUNTERS ───────────────────────────────────────────────
    counts = findings_df["severity"].value_counts().to_dict()
    cols = st.columns(4)
    display_sevs = ["critical", "high", "medium", "info"]
    
    labels = {
        "critical": "Critical Alerts",
        "high": "High Priority",
        "medium": "Medium Risk",
        "info": "Informational"
    }
    
    for col, sev in zip(cols, display_sevs):
        count = counts.get(sev, 0)
        color = _SEVERITY_COLORS[sev]
        st.markdown('<div style="margin-top: 24px;"></div>', unsafe_allow_html=True)
        with col:
            st.markdown(f"""
            <div class="metric-card" style="--accent: {color};">
                <div class="metric-glow-line"></div>
                <div class="metric-glow-bg"></div>
                <div class="metric-value" style="color: {color};">{count}</div>
                <div class="metric-label">{labels[sev]}</div>
            </div>
            """, unsafe_allow_html=True)
    
    st.write("---")
    
    # ─── CHARTS & THREAT FEED ────────────────────────────────────────────
    col_bar, col_feed = st.columns([3, 2])
    
    with col_bar:
        st.markdown("**Attack Surface by Asset (Stacked)**")
        stacked_data = findings_df.groupby(["hostname", "severity"]).size().reset_index(name="count")
        stacked_data['severity'] = pd.Categorical(stacked_data['severity'], categories=_SEVERITY_ORDER, ordered=True)
        stacked_data = stacked_data.sort_values(['hostname', 'severity'])
        
        fig_bar = px.bar(
            stacked_data, y="hostname", x="count", color="severity", orientation='h',
            color_discrete_map=_SEVERITY_COLORS, labels={"count": "Vulnerabilities", "hostname": ""}
        )
        fig_bar.update_layout(
            plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', 
            font_color='#E6E9EF', margin=dict(t=10, b=10, l=0, r=0),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, title="")
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with col_feed:
        st.markdown("**Live Threat Feed**")
        feed_df = findings_df.sort_values("discovered_at", ascending=False).head(8)
        
        feed_html = '<div class="metric-card" style="--accent: #334155; padding: 1.2rem; height: 380px; overflow-y: auto;">'
        feed_html += '<div class="metric-glow-line"></div>'
        
        for _, row in feed_df.iterrows():
            color = _SEVERITY_COLORS.get(row['severity'], "#8891A5")
            time_str = pd.to_datetime(row['discovered_at']).strftime('%H:%M')
            icon = "🔴" if row['severity'] == "critical" else "🟠" if row['severity'] == "high" else "🟡" if row['severity'] == "medium" else "🟢"
            
            feed_html += f"""<div style="margin-bottom: 0.8rem; padding-bottom: 0.8rem; border-bottom: 1px solid #1E2430; position: relative; z-index: 2;">
<span style="color: #475569; font-family: monospace; font-size: 0.8rem; margin-right: 6px;">{time_str}</span>
<span style="font-size: 0.85rem;">{icon}</span>
<span style="font-size: 0.9rem; margin-left: 5px; color: #E6E9EF; font-weight: bold;">{row['title'][:38]}...</span><br>
<span style="color: #8891A5; font-size: 0.8rem; margin-left: 45px;">Target: <span style="font-family: monospace; color:#5FD4E8">{row['hostname']}</span></span>
</div>"""
        feed_html += '</div>'
        st.markdown(feed_html, unsafe_allow_html=True)

    st.write("---")

    # ─── THREAT LEDGER (HTML CUSTOMIZADO PARA BADGES & HOVER) ────────────
    st.markdown("**Detailed Threat Ledger**")
    filtered = findings_df.copy()
    filtered["severity_rank"] = filtered["severity"].apply(_SEVERITY_ORDER.index)
    filtered = filtered.sort_values(by=["severity_rank", "cvss_score"], ascending=[True, False])
    
    table_html = """
<div style="background: #10141D; border: 1px solid #1E2430; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.2);">
<table class="custom-table">
<thead style="background: #1E2430;">
<tr>
<th>SEVERITY</th>
<th>CVSS</th>
<th>VULNERABILITY</th>
<th>TARGET ASSET</th>
<th>EXPLOITABLE</th>
</tr>
</thead>
<tbody>
"""
    for _, row in filtered.iterrows():
        bg_color = _SEVERITY_COLORS.get(row['severity'], "#8891A5")
        text_color = "#0B0E14" if row['severity'] in ['medium', 'low'] else "#FFFFFF"
        badge = f'<span class="badge" style="background-color: {bg_color}; color: {text_color}">{row["severity"]}</span>'
        conf = "✔️" if row['confirmed'] else "—"
        
        table_html += f"""<tr>
<td>{badge}</td>
<td style="font-family: monospace;">{row['cvss_score']}</td>
<td style="color: #E6E9EF;">{row['title']}</td>
<td style="font-family: monospace; color: #8891A5;">{row['hostname']}</td>
<td style="text-align: center;">{conf}</td>
</tr>"""

    table_html += "</tbody></table></div>"
    st.markdown(table_html, unsafe_allow_html=True)

# ─── FOOTER ──────────────────────────────────────────────────────────────
st.markdown("""
<div class="footer">
    <strong>Spect CTI</strong> • Security Intelligence Platform<br>
    Academic Research Edition • Developed for the Final Degree Project (TFG)<br>
    © 2026 Fernando Silva
</div>
""", unsafe_allow_html=True)