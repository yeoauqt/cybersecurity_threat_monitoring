import os
import streamlit as st
import pandas as pd
import duckdb
import plotly.express as px
import plotly.graph_objects as go


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Threat Monitoring",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# DESIGN TOKENS
# ============================================================

COLORS = {
    "bg": "#0B0F14",
    "surface": "#141B24",
    "surface_alt": "#0E131A",
    "border": "#2B3644",
    "text": "#F2F5F8",
    "text_dim": "#9BA9BA",
    "accent": "#5B9BFF",
}

RISK_COLORS = {
    "Critical": "#F0465A",
    "High": "#F59B4B",
    "Medium": "#F2C94C",
    "Low": "#4FCB8D",
}


def _risk_color(value):
    return RISK_COLORS.get(str(value).strip().title(), COLORS["text_dim"])


# ============================================================
# GLOBAL STYLES
# ============================================================

st.markdown(
    f"""
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@500;600&display=swap" rel="stylesheet">
    <style>
        html, body, [class*="css"] {{
            font-family: 'IBM Plex Sans', sans-serif;
        }}

        .stApp {{
            background-color: {COLORS['bg']};
            color: {COLORS['text']};
        }}

        section[data-testid="stSidebar"] {{
            background-color: {COLORS['surface_alt']};
            border-right: 1px solid {COLORS['border']};
        }}

        #MainMenu, footer {{visibility: hidden;}}

        .app-title {{
            font-size: 1.15rem;
            font-weight: 600;
            color: {COLORS['text']};
            letter-spacing: 0.01em;
            margin-bottom: 0;
        }}
        .app-subtitle {{
            font-size: 0.82rem;
            color: {COLORS['text_dim']};
            margin-top: 2px;
            margin-bottom: 18px;
        }}

        .section-header {{
            margin: 30px 0 14px 0;
            padding-bottom: 8px;
            border-bottom: 1px solid {COLORS['border']};
        }}
        .section-title {{
            font-size: 1.02rem;
            font-weight: 600;
            color: {COLORS['text']};
        }}
        .section-sub {{
            font-size: 0.84rem;
            color: {COLORS['text_dim']};
            margin-top: 2px;
        }}

        .kpi-card {{
            background-color: {COLORS['surface']};
            border: 1px solid {COLORS['border']};
            border-radius: 6px;
            padding: 16px 18px;
            height: 100%;
        }}
        .kpi-label {{
            font-size: 0.82rem;
            color: {COLORS['text_dim']};
            margin-bottom: 6px;
        }}
        .kpi-value {{
            font-family: 'IBM Plex Mono', monospace;
            font-size: 1.7rem;
            font-weight: 600;
            color: {COLORS['text']};
        }}
        .kpi-value.accent {{ color: {COLORS['accent']}; }}

        .badge {{
            display: inline-block;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.8rem;
            font-weight: 600;
            padding: 3px 10px;
            border-radius: 4px;
        }}

        [data-testid="stMetricValue"] {{
            font-family: 'IBM Plex Mono', monospace;
        }}

        .stTabs [data-baseweb="tab-list"] {{
            gap: 4px;
        }}

        div[data-baseweb="select"] > div {{
            background-color: {COLORS['surface']};
            border-color: {COLORS['border']};
        }}

        section[data-testid="stSidebar"] label p {{
            color: {COLORS['text']} !important;
            font-size: 0.92rem;
        }}

        p, span, label, div {{ color: {COLORS['text']}; }}

        [data-testid="stMetricLabel"] {{ color: {COLORS['text_dim']}; }}

        hr {{ border-color: {COLORS['border']}; }}
    </style>
    """,
    unsafe_allow_html=True,
)


def section_header(title, subtitle=None):
    sub_html = f'<div class="section-sub">{subtitle}</div>' if subtitle else ""
    html = f'<div class="section-header"><div class="section-title">{title}</div>{sub_html}</div>'
    st.markdown(html, unsafe_allow_html=True)


def page_header(title, subtitle):
    html = (
        f'<div class="app-title" style="font-size:1.4rem;">{title}</div>'
        f'<div class="app-subtitle">{subtitle}</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def kpi_card(col, label, value, accent=False):
    cls = "kpi-value accent" if accent else "kpi-value"
    html = f'<div class="kpi-card"><div class="kpi-label">{label}</div><div class="{cls}">{value}</div></div>'
    col.markdown(html, unsafe_allow_html=True)


def risk_badge(value):
    color = _risk_color(value)
    return (
        f'<span class="badge" style="background:{color}22;'
        f'color:{color};border:1px solid {color}55;">{value}</span>'
    )


def style_fig(fig, height=340):
    fig.update_layout(
        paper_bgcolor=COLORS["surface"],
        plot_bgcolor=COLORS["surface"],
        font=dict(family="IBM Plex Sans, sans-serif", color=COLORS["text"], size=12),
        title=dict(font=dict(size=14, color=COLORS["text"])),
        margin=dict(l=10, r=10, t=45, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        height=height,
    )
    fig.update_xaxes(gridcolor=COLORS["border"], zeroline=False, linecolor=COLORS["border"])
    fig.update_yaxes(gridcolor=COLORS["border"], zeroline=False, linecolor=COLORS["border"])
    return fig


def styled_table(df, badge_cols=None):
    """Return a pandas Styler with severity/risk columns tinted by color."""
    badge_cols = [c for c in (badge_cols or []) if c in df.columns]
    styler = df.style.hide(axis="index")

    if not badge_cols:
        return styler

    def _tint(val):
        color = RISK_COLORS.get(str(val).strip().title())
        if not color:
            return ""
        return f"background-color:{color}22;color:{color};font-weight:600"

    try:
        styler = styler.map(_tint, subset=badge_cols)
    except AttributeError:
        styler = styler.applymap(_tint, subset=badge_cols)
    return styler


# ============================================================
# LOAD DATA FROM WAREHOUSE
# ============================================================

WAREHOUSE_DIR = "data/warehouse"

REQUIRED_FILES = {
    "fact": "fact_security_event.parquet",
    "dim_attack": "dim_attack.parquet",
    "dim_ip": "dim_ip.parquet",
    "dim_network": "dim_network.parquet",
    "dim_time": "dim_time.parquet",
}

REQUIRED_COLUMNS = {
    "fact": [
        "event_id", "timestamp", "attack_id", "source_ip_id",
        "destination_ip_id", "network_id", "time_id",
        "packet_length", "anomaly_score", "severity_level",
        "action_taken", "malware_indicator", "alert_triggered",
        "firewall_log_present", "ids_ips_alert_present",
        "proxy_present", "connection_type",
    ],
    "dim_attack": ["attack_id", "Attack Type", "Attack Signature"],
    "dim_ip": ["ip_id", "ip_address", "is_private"],
    "dim_network": [
        "network_id", "Network Segment", "Protocol",
        "Traffic Type", "Packet Type", "Log Source",
    ],
    "dim_time": [
        "time_id", "event_date", "event_hour",
        "day_of_week", "month", "is_weekend",
    ],
}


def _load_parquet_or_raise(label, filename):
    path = os.path.join(WAREHOUSE_DIR, filename)

    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Missing warehouse file for '{label}': expected it at "
            f"'{path}' (cwd={os.getcwd()}). Make sure the parquet "
            f"files are committed to the repo (they are often "
            f"excluded via .gitignore) and that the path is "
            f"relative to the repo root on Streamlit Cloud."
        )

    df = pd.read_parquet(path)

    missing = [col for col in REQUIRED_COLUMNS[label] if col not in df.columns]

    if missing:
        raise KeyError(
            f"Table '{label}' ({path}) is missing expected column(s): "
            f"{missing}. Columns actually present: "
            f"{sorted(df.columns.tolist())}"
        )

    return df


@st.cache_data
def load_data():
    fact = _load_parquet_or_raise("fact", REQUIRED_FILES["fact"])
    dim_attack = _load_parquet_or_raise("dim_attack", REQUIRED_FILES["dim_attack"])
    dim_ip = _load_parquet_or_raise("dim_ip", REQUIRED_FILES["dim_ip"])
    dim_network = _load_parquet_or_raise("dim_network", REQUIRED_FILES["dim_network"])
    dim_time = _load_parquet_or_raise("dim_time", REQUIRED_FILES["dim_time"])

    con = duckdb.connect()

    con.register("fact_security_event", fact)
    con.register("dim_attack", dim_attack)
    con.register("dim_ip", dim_ip)
    con.register("dim_network", dim_network)
    con.register("dim_time", dim_time)

    query = """
    SELECT
        f.event_id,
        f.timestamp AS "Timestamp",

        src.ip_address AS source_ip,
        src.is_private AS source_ip_is_private,

        dst.ip_address AS destination_ip,
        dst.is_private AS destination_ip_is_private,

        a."Attack Type" AS attack_type,
        a."Attack Signature" AS attack_signature,

        n."Network Segment" AS network_segment,
        n.Protocol AS protocol,
        n."Traffic Type" AS traffic_type,
        n."Packet Type" AS packet_type,
        n."Log Source" AS log_source,

        t.event_date,
        t.event_hour,
        t.day_of_week,
        t.month,
        t.is_weekend,

        f.packet_length AS packet_length,
        f.anomaly_score AS anomaly_score,
        f.severity_level AS severity_level,
        f.action_taken AS action_taken,

        f.malware_indicator,
        f.alert_triggered,
        f.firewall_log_present,
        f.ids_ips_alert_present,
        f.proxy_present,
        f.connection_type

    FROM fact_security_event f

    LEFT JOIN dim_attack a
        ON f.attack_id = a.attack_id

    LEFT JOIN dim_ip src
        ON f.source_ip_id = src.ip_id

    LEFT JOIN dim_ip dst
        ON f.destination_ip_id = dst.ip_id

    LEFT JOIN dim_network n
        ON f.network_id = n.network_id

    LEFT JOIN dim_time t
        ON f.time_id = t.time_id
    """

    try:
        df = con.execute(query).df()
    except duckdb.Error as e:
        raise RuntimeError(
            f"DuckDB query failed: {e}\n\n"
            f"fact columns: {sorted(fact.columns.tolist())}\n"
            f"dim_attack columns: {sorted(dim_attack.columns.tolist())}\n"
            f"dim_ip columns: {sorted(dim_ip.columns.tolist())}\n"
            f"dim_network columns: {sorted(dim_network.columns.tolist())}\n"
            f"dim_time columns: {sorted(dim_time.columns.tolist())}"
        ) from e
    finally:
        con.close()

    return df


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk(df):
    df = df.copy()

    df["risk_score"] = (
        (df["severity_level"].astype(str).str.lower().eq("high")).astype(int) * 30
        + (df["anomaly_score"] > 80).astype(int) * 25
        + (df["malware_indicator"] == 1).astype(int) * 20
        + (df["ids_ips_alert_present"] == 1).astype(int) * 15
        + (df["alert_triggered"] == 1).astype(int) * 10
    )

    def assign_risk_level(score):
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 30:
            return "Medium"
        else:
            return "Low"

    df["risk_level"] = df["risk_score"].apply(assign_risk_level)
    df["is_suspicious"] = df["risk_score"] >= 30

    return df


# ============================================================
# LOAD + PREPARE DATA
# ============================================================

try:
    df = load_data()
    df = calculate_risk(df)

except Exception as e:
    st.error("Unable to load warehouse data.")
    st.exception(e)

    with st.expander("Debug: raw columns in each warehouse file"):
        for label, filename in REQUIRED_FILES.items():
            path = os.path.join(WAREHOUSE_DIR, filename)
            if os.path.exists(path):
                try:
                    cols = sorted(pd.read_parquet(path).columns.tolist())
                    st.write(f"**{label}** (`{path}`): {cols}")
                except Exception as read_err:
                    st.write(f"**{label}** (`{path}`): could not read — {read_err}")
            else:
                st.write(f"**{label}** (`{path}`): file not found")

    st.stop()


# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

st.sidebar.markdown(
    '<div class="app-title">Threat Monitoring</div>'
    '<div class="app-subtitle">Security event analytics</div>',
    unsafe_allow_html=True,
)

page = st.sidebar.radio(
    "Navigation",
    ["Overview", "Alerts", "Investigation", "Event detail"],
    label_visibility="collapsed",
)

st.sidebar.markdown(f"<hr>", unsafe_allow_html=True)
st.sidebar.markdown(
    f"<div class='app-subtitle'>{len(df):,} events loaded</div>",
    unsafe_allow_html=True,
)


# ============================================================
# OVERVIEW
# ============================================================

if page == "Overview":

    page_header("Security overview", "Event volume, severity, and traffic across the monitored network")

    total_events = len(df)
    high_risk = len(df[df["risk_level"].isin(["Critical", "High"])])
    malware = int((df["malware_indicator"] == 1).sum())
    alerts = int((df["alert_triggered"] == 1).sum())

    c1, c2, c3, c4 = st.columns(4)
    kpi_card(c1, "Total events", f"{total_events:,}")
    kpi_card(c2, "High risk", f"{high_risk:,}", accent=True)
    kpi_card(c3, "Malware indicators", f"{malware:,}")
    kpi_card(c4, "Alerts triggered", f"{alerts:,}")

    section_header("Events over time")
    daily_events = df.groupby("event_date").size().reset_index(name="events")
    fig = px.line(daily_events, x="event_date", y="events")
    fig.update_traces(line_color=COLORS["accent"], line_width=2.2)
    st.plotly_chart(style_fig(fig), use_container_width=True)

    col1, col2 = st.columns(2)

    with col1:
        section_header("Attack type distribution")
        attack_counts = df["attack_type"].value_counts().reset_index()
        attack_counts.columns = ["attack_type", "events"]
        fig_attack = px.bar(attack_counts, x="attack_type", y="events")
        fig_attack.update_traces(marker_color=COLORS["accent"])
        st.plotly_chart(style_fig(fig_attack), use_container_width=True)

    with col2:
        section_header("Severity level")
        severity_counts = df["severity_level"].value_counts().reset_index()
        severity_counts.columns = ["severity", "events"]
        fig_severity = px.bar(
            severity_counts, x="severity", y="events",
            color="severity", color_discrete_map=RISK_COLORS,
        )
        fig_severity.update_layout(showlegend=False)
        st.plotly_chart(style_fig(fig_severity), use_container_width=True)

    col3, col4 = st.columns(2)

    with col3:
        section_header("Protocol distribution")
        protocol_counts = df["protocol"].value_counts().reset_index()
        protocol_counts.columns = ["protocol", "events"]
        fig_protocol = go.Figure(
            data=[go.Pie(
                labels=protocol_counts["protocol"],
                values=protocol_counts["events"],
                hole=0.55,
                marker=dict(line=dict(color=COLORS["surface"], width=2)),
            )]
        )
        st.plotly_chart(style_fig(fig_protocol), use_container_width=True)

    with col4:
        section_header("Action taken")
        action_counts = df["action_taken"].value_counts().reset_index()
        action_counts.columns = ["action", "events"]
        fig_action = px.bar(action_counts, x="events", y="action", orientation="h")
        fig_action.update_traces(marker_color=COLORS["accent"])
        fig_action.update_layout(yaxis=dict(categoryorder="total ascending"))
        st.plotly_chart(style_fig(fig_action), use_container_width=True)


# ============================================================
# ALERTS
# ============================================================

elif page == "Alerts":

    page_header("Threat alerts", "Suspicious events, ranked by risk score")

    alerts_df = df[df["is_suspicious"]].copy()
    alerts_df = alerts_df.sort_values(by=["risk_score", "Timestamp"], ascending=[False, False])

    critical_count = int((alerts_df["risk_level"] == "Critical").sum())
    high_count = int((alerts_df["risk_level"] == "High").sum())

    c1, c2, c3 = st.columns(3)
    kpi_card(c1, "Suspicious events", f"{len(alerts_df):,}")
    kpi_card(c2, "Critical", f"{critical_count:,}", accent=True)
    kpi_card(c3, "High", f"{high_count:,}")

    section_header("Flagged events")

    display_columns = [
        "event_id", "Timestamp", "source_ip", "destination_ip",
        "attack_type", "severity_level", "anomaly_score",
        "risk_score", "risk_level", "action_taken",
    ]

    if alerts_df.empty:
        st.info("No events currently meet the suspicious threshold.")
    else:
        st.dataframe(
            styled_table(alerts_df[display_columns], badge_cols=["risk_level", "severity_level"]),
            use_container_width=True,
        )


# ============================================================
# INVESTIGATION
# ============================================================

elif page == "Investigation":

    page_header("Threat investigation", "Filter events to investigate a specific pattern")

    with st.container(border=True):
        col1, col2, col3 = st.columns(3)

        source_options = sorted(df["source_ip"].dropna().astype(str).unique().tolist())
        destination_options = sorted(df["destination_ip"].dropna().astype(str).unique().tolist())
        protocol_options = sorted(df["protocol"].dropna().astype(str).unique().tolist())

        selected_source = col1.selectbox("Source IP", ["All"] + source_options)
        selected_destination = col2.selectbox("Destination IP", ["All"] + destination_options)
        selected_protocol = col3.selectbox("Protocol", ["All"] + protocol_options)

        col1, col2, col3 = st.columns(3)

        attack_options = sorted(df["attack_type"].dropna().astype(str).unique().tolist())
        severity_options = sorted(df["severity_level"].dropna().astype(str).unique().tolist())
        network_options = sorted(df["network_segment"].dropna().astype(str).unique().tolist())

        selected_attack = col1.selectbox("Attack type", ["All"] + attack_options)
        selected_severity = col2.selectbox("Severity", ["All"] + severity_options)
        selected_network = col3.selectbox("Network segment", ["All"] + network_options)

        col1, col2 = st.columns(2)

        connection_options = sorted(df["connection_type"].dropna().astype(str).unique().tolist())

        selected_connection = col1.selectbox("Connection type", ["All"] + connection_options)
        selected_risk = col2.selectbox("Risk level", ["All", "Critical", "High", "Medium", "Low"])

    filtered = df.copy()

    if selected_source != "All":
        filtered = filtered[filtered["source_ip"].astype(str) == selected_source]

    if selected_destination != "All":
        filtered = filtered[filtered["destination_ip"].astype(str) == selected_destination]

    if selected_protocol != "All":
        filtered = filtered[filtered["protocol"].astype(str) == selected_protocol]

    if selected_attack != "All":
        filtered = filtered[filtered["attack_type"].astype(str) == selected_attack]

    if selected_severity != "All":
        filtered = filtered[filtered["severity_level"].astype(str) == selected_severity]

    if selected_network != "All":
        filtered = filtered[filtered["network_segment"].astype(str) == selected_network]

    if selected_connection != "All":
        filtered = filtered[filtered["connection_type"].astype(str) == selected_connection]

    if selected_risk != "All":
        filtered = filtered[filtered["risk_level"] == selected_risk]

    filtered = filtered.sort_values(by=["risk_score", "Timestamp"], ascending=[False, False])

    section_header("Results", f"{len(filtered):,} matching events")

    display_columns = [
        "event_id", "Timestamp", "source_ip", "destination_ip", "protocol",
        "attack_type", "severity_level", "anomaly_score",
        "risk_score", "risk_level", "action_taken",
    ]

    if filtered.empty:
        st.info("No events match the current filters. Try widening your criteria.")
    else:
        st.dataframe(
            styled_table(filtered[display_columns], badge_cols=["risk_level", "severity_level"]),
            use_container_width=True,
        )


# ============================================================
# EVENT DETAIL
# ============================================================

elif page == "Event detail":

    page_header("Event detail", "Look up a single event to inspect its full context")

    event_ids = df["event_id"].dropna().astype(str).tolist()
    selected_event = st.selectbox("Event ID", event_ids)

    event = df[df["event_id"].astype(str) == selected_event]

    if not event.empty:
        row = event.iloc[0]

        section_header("Risk assessment")

        c1, c2, c3 = st.columns(3)
        kpi_card(c1, "Risk score", int(row["risk_score"]), accent=True)
        c2.markdown(
            f'<div class="kpi-card"><div class="kpi-label">Risk level</div>'
            f'<div style="margin-top:6px;">{risk_badge(row["risk_level"])}</div></div>',
            unsafe_allow_html=True,
        )
        kpi_card(c3, "Suspicious", "Yes" if row["is_suspicious"] else "No")

        section_header("Event information")

        details = {
            "Event ID": row["event_id"],
            "Timestamp": row["Timestamp"],
            "Source IP": row["source_ip"],
            "Destination IP": row["destination_ip"],
            "Protocol": row["protocol"],
            "Attack type": row["attack_type"],
            "Attack signature": row["attack_signature"],
            "Severity level": row["severity_level"],
            "Anomaly score": row["anomaly_score"],
            "Network segment": row["network_segment"],
            "Connection type": row["connection_type"],
            "Packet length": row["packet_length"],
            "Malware indicator": row["malware_indicator"],
            "IDS/IPS alert": row["ids_ips_alert_present"],
            "Firewall log": row["firewall_log_present"],
            "Alert triggered": row["alert_triggered"],
            "Proxy present": row["proxy_present"],
            "Action taken": row["action_taken"],
        }

        details_df = pd.DataFrame(details.items(), columns=["Field", "Value"])

        st.dataframe(details_df, use_container_width=True, hide_index=True)

        st.info("Investigation focus: what happened, and how concerning is this event?")
