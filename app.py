import os
import streamlit as st
import pandas as pd
import duckdb
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image, ImageDraw


# ============================================================
# FAVICON
# A small monochrome shield mark drawn as geometry (no emoji),
# rendered at 4x and downsampled for a clean, anti-aliased edge.
# ============================================================

def _build_favicon(color="#2F6FED", size=64, supersample=4):
    s = size * supersample
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    points = [
        (0.50 * s, 0.07 * s),
        (0.85 * s, 0.22 * s),
        (0.85 * s, 0.53 * s),
        (0.50 * s, 0.93 * s),
        (0.15 * s, 0.53 * s),
        (0.15 * s, 0.22 * s),
    ]
    stroke_width = max(2, int(0.05 * s))
    draw.line(points + [points[0]], fill=color, width=stroke_width, joint="curve")
    return img.resize((size, size), Image.LANCZOS)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Threat Monitoring",
    page_icon=_build_favicon(),
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# DESIGN TOKENS
# A light, professional dashboard theme: easier to scan for long
# tables of security events than a dark "hacker" theme, and it keeps
# Streamlit's native widgets (selectboxes, tables, buttons) rendering
# the way they're designed to, instead of fighting them with overrides.
# ============================================================

COLORS = {
    "bg": "#F6F8FB",
    "surface": "#FFFFFF",
    "border": "#E2E8F0",
    "text": "#1A2233",
    "text_dim": "#647087",
    "accent": "#2F6FED",
    "accent_soft": "#EAF1FE",
}

RISK_COLORS = {
    "Critical": "#DC2626",
    "High": "#EA580C",
    "Medium": "#B45309",
    "Low": "#16A34A",
}

RISK_ORDER = ["Critical", "High", "Medium", "Low"]

ACTION_COLORS = {
    "Blocked": "#DC2626",
    "Ignored": "#94A3B8",
    "Logged": "#2F6FED",
}

ATTACK_PALETTE = ["#2F6FED", "#7CA6F4", "#1A2233", "#B7CDFA", "#647087"]
PROTOCOL_PALETTE = ["#2F6FED", "#7CA6F4", "#B7CDFA", "#1A2233", "#647087"]

# Column keys -> human-readable table headers (no more raw_snake_case)
COLUMN_LABELS = {
    "event_id": "Event ID",
    "Timestamp": "Timestamp",
    "source_ip": "Source IP",
    "destination_ip": "Destination IP",
    "protocol": "Protocol",
    "attack_type": "Attack Type",
    "attack_signature": "Attack Signature",
    "severity_level": "Severity",
    "anomaly_score": "Anomaly Score",
    "risk_score": "Risk Score",
    "risk_level": "Risk Level",
    "action_taken": "Action Taken",
    "network_segment": "Network Segment",
    "connection_type": "Connection Type",
    "packet_length": "Packet Length",
    "traffic_type": "Traffic Type",
    "packet_type": "Packet Type",
    "log_source": "Log Source",
}

# Small feather-style outline icons (MIT-licensed style geometry),
# used on the KPI cards so the overview reads at a glance.
ICONS = {
    "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>'
              '<polyline points="2 17 12 22 22 17"></polyline>'
              '<polyline points="2 12 12 17 22 12"></polyline>',
    "alert": '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>'
             '<line x1="12" y1="9" x2="12" y2="13"></line>'
             '<line x1="12" y1="17" x2="12.01" y2="17"></line>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>',
    "bell": '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>'
            '<path d="M13.73 21a2 2 0 0 1-3.46 0"></path>',
    "search": '<circle cx="11" cy="11" r="8"></circle>'
              '<line x1="21" y1="21" x2="16.65" y2="16.65"></line>',
    "file": '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>'
            '<polyline points="13 2 13 9 20 9"></polyline>',
}


def icon_svg(name, color=None, size=18):
    color = color or COLORS["text_dim"]
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round">{ICONS[name]}</svg>'
    )


def _risk_color(value):
    return RISK_COLORS.get(str(value).strip().title(), COLORS["text_dim"])


def _action_color(value):
    return ACTION_COLORS.get(str(value).strip().title(), COLORS["text_dim"])


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
        .stApp {{ background-color: {COLORS['bg']}; }}
        #MainMenu, footer {{ visibility: hidden; }}

        .block-container {{ padding-top: 2.2rem; padding-bottom: 3rem; }}

        .app-title-row {{
            display: flex;
            align-items: center;
            gap: 9px;
            margin-bottom: 2px;
        }}
        .app-title {{
            font-size: 1.15rem;
            font-weight: 700;
            color: {COLORS['text']};
            letter-spacing: -0.01em;
        }}
        .app-subtitle {{
            font-size: 0.82rem;
            color: {COLORS['text_dim']};
            margin-top: 3px;
            margin-bottom: 22px;
            line-height: 1.4;
        }}
        .page-eyebrow {{
            font-size: 0.76rem;
            font-weight: 600;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            color: {COLORS['accent']};
            margin-bottom: 6px;
        }}
        .page-title {{
            font-size: 1.9rem;
            font-weight: 700;
            color: {COLORS['text']};
            margin-bottom: 3px;
            letter-spacing: -0.02em;
        }}
        .page-subtitle {{
            font-size: 0.97rem;
            color: {COLORS['text_dim']};
            margin-bottom: 24px;
        }}

        .section-header {{
            margin: 32px 0 12px 0;
        }}
        .section-title {{
            font-size: 1.02rem;
            font-weight: 600;
            color: {COLORS['text']};
        }}
        .section-sub {{
            font-size: 0.82rem;
            color: {COLORS['text_dim']};
            margin-top: 1px;
        }}

        /* ---- KPI cards ---- */
        .kpi-card {{
            background-color: {COLORS['surface']};
            border: 1px solid {COLORS['border']};
            border-radius: 14px;
            padding: 18px 20px;
            height: 100%;
            box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
            transition: box-shadow 0.15s ease, transform 0.15s ease;
        }}
        .kpi-card:hover {{
            box-shadow: 0 6px 16px rgba(16, 24, 40, 0.08);
            transform: translateY(-1px);
        }}
        .kpi-top-row {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
        }}
        .kpi-label {{
            font-size: 0.82rem;
            color: {COLORS['text_dim']};
            font-weight: 500;
        }}
        .kpi-icon-wrap {{
            width: 30px;
            height: 30px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }}
        .kpi-value {{
            font-family: 'IBM Plex Mono', monospace;
            font-size: 1.85rem;
            font-weight: 600;
            color: {COLORS['text']};
            line-height: 1.1;
        }}
        .kpi-value.accent {{ color: {COLORS['accent']}; }}
        .kpi-note {{
            font-size: 0.76rem;
            color: {COLORS['text_dim']};
            margin-top: 6px;
        }}

        .badge {{
            display: inline-block;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.8rem;
            font-weight: 600;
            padding: 4px 12px;
            border-radius: 6px;
        }}

        .legend-row {{ margin-bottom: 18px; display: flex; flex-wrap: wrap; }}
        .legend-chip {{
            display: inline-flex;
            align-items: center;
            font-size: 0.82rem;
            color: {COLORS['text_dim']};
            margin-right: 18px;
            font-weight: 500;
        }}
        .legend-dot {{
            display: inline-block;
            width: 9px;
            height: 9px;
            border-radius: 50%;
            margin-right: 6px;
        }}

        .help-box {{
            background-color: {COLORS['accent_soft']};
            border: 1px solid {COLORS['border']};
            border-left: 3px solid {COLORS['accent']};
            border-radius: 10px;
            padding: 13px 16px;
            font-size: 0.87rem;
            color: {COLORS['text']};
            margin-bottom: 18px;
            display: flex;
            gap: 10px;
            align-items: flex-start;
        }}

        .empty-state {{
            background-color: {COLORS['surface']};
            border: 1px dashed {COLORS['border']};
            border-radius: 12px;
            padding: 34px 20px;
            text-align: center;
            color: {COLORS['text_dim']};
        }}

        /* ---- Sidebar ---- */
        section[data-testid="stSidebar"] {{
            border-right: 1px solid {COLORS['border']};
        }}
        section[data-testid="stSidebar"] .block-container {{
            padding-top: 2rem;
        }}

        /* Turn the plain radio list into a modern pill-style nav:
           hide the native circle indicator, make each label a
           full-width row, and highlight the selected one. */
        section[data-testid="stSidebar"] div[role="radiogroup"] {{
            gap: 2px;
        }}
        section[data-testid="stSidebar"] div[role="radiogroup"] label {{
            width: 100%;
            padding: 9px 12px;
            border-radius: 8px;
            transition: background-color 0.12s ease;
        }}
        section[data-testid="stSidebar"] div[role="radiogroup"] label:hover {{
            background-color: {COLORS['bg']};
        }}
        section[data-testid="stSidebar"] div[role="radiogroup"] label > div:first-child {{
            display: none;
        }}
        section[data-testid="stSidebar"] div[role="radiogroup"] label p {{
            font-size: 0.92rem;
            color: {COLORS['text_dim']};
            font-weight: 500;
        }}
        section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {{
            background-color: {COLORS['accent']}14;
        }}
        section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p {{
            color: {COLORS['accent']};
            font-weight: 600;
        }}

        [data-testid="stMetricValue"] {{ font-family: 'IBM Plex Mono', monospace; }}

        div[data-testid="stDataFrame"] {{
            border: 1px solid {COLORS['border']};
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
        }}

        div[data-testid="stExpander"] {{
            border: 1px solid {COLORS['border']};
            border-radius: 12px;
        }}

        div[data-baseweb="select"] > div {{
            border-radius: 8px;
            border-color: {COLORS['border']};
        }}

        div[data-testid="stVerticalBlockBorderWrapper"] {{
            border-radius: 14px !important;
        }}

        label[data-testid="stWidgetLabel"] p {{
            font-size: 0.82rem;
            font-weight: 600;
            color: {COLORS['text_dim']};
        }}
    </style>
    """,
    unsafe_allow_html=True,
)


def page_header(eyebrow, title, subtitle):
    html = (
        f'<div class="page-eyebrow">{eyebrow}</div>'
        f'<div class="page-title">{title}</div>'
        f'<div class="page-subtitle">{subtitle}</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def section_header(title, subtitle=None):
    sub_html = f'<div class="section-sub">{subtitle}</div>' if subtitle else ""
    html = f'<div class="section-header"><div class="section-title">{title}</div>{sub_html}</div>'
    st.markdown(html, unsafe_allow_html=True)


def kpi_card(col, label, value, note=None, accent=False, icon=None, icon_color=None):
    cls = "kpi-value accent" if accent else "kpi-value"
    note_html = f'<div class="kpi-note">{note}</div>' if note else ""

    icon_html = ""
    if icon:
        icon_color = icon_color or COLORS["accent"]
        icon_html = (
            f'<div class="kpi-icon-wrap" style="background:{icon_color}17;">'
            f'{icon_svg(icon, color=icon_color, size=16)}</div>'
        )

    html = (
        '<div class="kpi-card">'
        f'<div class="kpi-top-row"><div class="kpi-label">{label}</div>{icon_html}</div>'
        f'<div class="{cls}">{value}</div>{note_html}</div>'
    )
    col.markdown(html, unsafe_allow_html=True)


def risk_badge(value):
    color = _risk_color(value)
    return (
        f'<span class="badge" style="background:{color}1A;'
        f'color:{color};border:1px solid {color}55;">{value}</span>'
    )


def risk_legend():
    chips = "".join(
        f'<span class="legend-chip"><span class="legend-dot" '
        f'style="background:{RISK_COLORS[level]};"></span>{level}</span>'
        for level in RISK_ORDER
    )
    st.markdown(f'<div class="legend-row">{chips}</div>', unsafe_allow_html=True)


def help_box(text):
    html = (
        '<div class="help-box">'
        f'<div style="margin-top:1px;">{icon_svg("search", color=COLORS["accent"], size=16)}</div>'
        f'<div>{text}</div></div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def empty_state(text, icon="file"):
    html = (
        f'<div class="empty-state">{icon_svg(icon, color=COLORS["text_dim"], size=26)}'
        f'<div style="margin-top:10px;">{text}</div></div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def style_fig(fig, height=340, show_legend=True, x_title=None, y_title=None):
    fig.update_layout(
        paper_bgcolor=COLORS["surface"],
        plot_bgcolor=COLORS["surface"],
        font=dict(family="IBM Plex Sans, sans-serif", color=COLORS["text"], size=12),
        title=dict(font=dict(size=14, color=COLORS["text"])),
        margin=dict(l=10, r=10, t=10, b=10),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        showlegend=show_legend,
        height=height,
        hoverlabel=dict(
            bgcolor=COLORS["surface"],
            font=dict(family="IBM Plex Sans, sans-serif", color=COLORS["text"]),
            bordercolor=COLORS["border"],
        ),
    )
    fig.update_xaxes(
        gridcolor=COLORS["border"], zeroline=False, linecolor=COLORS["border"],
        title=dict(text=x_title, font=dict(size=12, color=COLORS["text_dim"])) if x_title else None,
    )
    fig.update_yaxes(
        gridcolor=COLORS["border"], zeroline=False, linecolor=COLORS["border"],
        title=dict(text=y_title, font=dict(size=12, color=COLORS["text_dim"])) if y_title else None,
    )
    return fig


def chart_panel():
    return st.container(border=True)


def format_table(df_subset, columns):
    """Return a display-ready copy: readable headers, tidy values."""
    out = df_subset[columns].copy()

    if "Timestamp" in out.columns:
        out["Timestamp"] = pd.to_datetime(out["Timestamp"]).dt.strftime("%Y-%m-%d %H:%M")
    if "anomaly_score" in out.columns:
        out["anomaly_score"] = out["anomaly_score"].round(1)
    if "risk_score" in out.columns:
        out["risk_score"] = out["risk_score"].astype(int)

    out = out.rename(columns=COLUMN_LABELS)
    return out


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
    '<div class="app-title-row">'
    f'{icon_svg("shield", color=COLORS["accent"], size=20)}'
    '<span class="app-title">Threat Monitoring</span></div>'
    '<div class="app-subtitle">Security event analytics for the monitored network</div>',
    unsafe_allow_html=True,
)

NAV_ITEMS = {
    "Overview": "Volume, severity, and traffic trends",
    "Alerts": "Events that need attention now",
    "Investigation": "Search and filter every event",
    "Event detail": "Look up one event by ID",
}

page = st.sidebar.radio(
    "Navigation",
    list(NAV_ITEMS.keys()),
    label_visibility="collapsed",
)

st.sidebar.caption(NAV_ITEMS[page])
st.sidebar.divider()
st.sidebar.caption(f"{len(df):,} events loaded from the warehouse")

with st.sidebar.expander("How risk is scored"):
    st.markdown(
        "Each event earns points toward a 0–100 risk score:\n"
        "- Severity marked **High** → +30\n"
        "- Anomaly score above 80 → +25\n"
        "- Malware indicator present → +20\n"
        "- IDS/IPS alert present → +15\n"
        "- Alert triggered → +10\n\n"
        "Score of 80+ is **Critical**, 60+ **High**, 30+ **Medium**, "
        "below that is **Low**. Events scoring 30 or higher are "
        "flagged as suspicious."
    )


# ============================================================
# OVERVIEW
# ============================================================

if page == "Overview":

    page_header(
        "Overview",
        "Network activity at a glance",
        "How much is happening, how severe it is, and where it's coming from",
    )

    total_events = len(df)
    high_risk = len(df[df["risk_level"].isin(["Critical", "High"])])
    malware = int((df["malware_indicator"] == 1).sum())
    alerts = int((df["alert_triggered"] == 1).sum())

    c1, c2, c3, c4 = st.columns(4)
    kpi_card(c1, "Total events", f"{total_events:,}", "All logged events in range",
              icon="layers", icon_color=COLORS["accent"])
    kpi_card(c2, "High risk", f"{high_risk:,}", "Critical + High risk level",
              accent=True, icon="alert", icon_color=RISK_COLORS["High"])
    kpi_card(c3, "Malware indicators", f"{malware:,}", "Events flagging malware",
              icon="shield", icon_color=RISK_COLORS["Critical"])
    kpi_card(c4, "Alerts triggered", f"{alerts:,}", "Events that fired an alert",
              icon="bell", icon_color=COLORS["accent"])

    section_header("Events over time", "Daily event volume across the full period")
    with chart_panel():
        daily_events = df.groupby("event_date").size().reset_index(name="events")
        fig = px.line(daily_events, x="event_date", y="events")
        fig.update_traces(
            line_color=COLORS["accent"], line_width=2.2,
            hovertemplate="%{x|%b %d, %Y}<br><b>%{y} events</b><extra></extra>",
        )
        st.plotly_chart(
            style_fig(fig, show_legend=False, x_title="Date", y_title="Events"),
            use_container_width=True,
        )

    col1, col2 = st.columns(2)

    with col1:
        section_header("Attack type", "Which attack types occur most often")
        with chart_panel():
            attack_counts = df["attack_type"].value_counts().reset_index()
            attack_counts.columns = ["attack_type", "events"]
            fig_attack = px.bar(attack_counts, x="attack_type", y="events")
            fig_attack.update_traces(
                marker_color=ATTACK_PALETTE[: len(attack_counts)],
                hovertemplate="<b>%{x}</b><br>%{y} events<extra></extra>",
            )
            st.plotly_chart(
                style_fig(fig_attack, show_legend=False, x_title="Attack Type", y_title="Events"),
                use_container_width=True,
            )

    with col2:
        section_header("Severity level", "Split of events by severity")
        with chart_panel():
            severity_counts = df["severity_level"].value_counts().reset_index()
            severity_counts.columns = ["severity", "events"]
            fig_severity = px.bar(
                severity_counts, x="severity", y="events",
                color="severity", color_discrete_map=RISK_COLORS,
            )
            fig_severity.update_traces(hovertemplate="<b>%{x}</b><br>%{y} events<extra></extra>")
            st.plotly_chart(
                style_fig(fig_severity, show_legend=False, x_title="Severity", y_title="Events"),
                use_container_width=True,
            )

    col3, col4 = st.columns(2)

    with col3:
        section_header("Protocol", "Share of traffic by protocol")
        with chart_panel():
            protocol_counts = df["protocol"].value_counts().reset_index()
            protocol_counts.columns = ["protocol", "events"]
            fig_protocol = go.Figure(
                data=[go.Pie(
                    labels=protocol_counts["protocol"],
                    values=protocol_counts["events"],
                    hole=0.6,
                    marker=dict(
                        colors=PROTOCOL_PALETTE,
                        line=dict(color=COLORS["surface"], width=2),
                    ),
                    hovertemplate="<b>%{label}</b><br>%{value} events (%{percent})<extra></extra>",
                    textinfo="percent",
                )]
            )
            fig_protocol.add_annotation(
                text=f"{protocol_counts['events'].sum():,}<br><span style='font-size:11px;color:{COLORS['text_dim']}'>events</span>",
                showarrow=False,
                font=dict(size=18, color=COLORS["text"], family="IBM Plex Mono, monospace"),
            )
            st.plotly_chart(style_fig(fig_protocol), use_container_width=True)

    with col4:
        section_header("Action taken", "What was done in response to each event")
        with chart_panel():
            action_counts = df["action_taken"].value_counts().reset_index()
            action_counts.columns = ["action", "events"]
            action_counts = action_counts.sort_values("events")
            fig_action = px.bar(action_counts, x="events", y="action", orientation="h")
            fig_action.update_traces(
                marker_color=[_action_color(a) for a in action_counts["action"]],
                hovertemplate="<b>%{y}</b><br>%{x} events<extra></extra>",
            )
            st.plotly_chart(
                style_fig(fig_action, show_legend=False, x_title="Events", y_title=None),
                use_container_width=True,
            )


# ============================================================
# ALERTS
# ============================================================

elif page == "Alerts":

    page_header(
        "Alerts",
        "Events that need attention",
        "Events with a risk score of 30 or higher, most urgent first",
    )

    alerts_df = df[df["is_suspicious"]].copy()
    alerts_df = alerts_df.sort_values(by=["risk_score", "Timestamp"], ascending=[False, False])

    critical_count = int((alerts_df["risk_level"] == "Critical").sum())
    high_count = int((alerts_df["risk_level"] == "High").sum())

    c1, c2, c3 = st.columns(3)
    kpi_card(c1, "Suspicious events", f"{len(alerts_df):,}", "Risk score 30 or higher",
              icon="search", icon_color=COLORS["accent"])
    kpi_card(c2, "Critical", f"{critical_count:,}", "Needs immediate review",
              accent=True, icon="alert", icon_color=RISK_COLORS["Critical"])
    kpi_card(c3, "High", f"{high_count:,}", "Review soon",
              icon="alert", icon_color=RISK_COLORS["High"])

    section_header("Flagged events", "Sorted by risk score, highest first")
    risk_legend()

    display_columns = [
        "event_id", "Timestamp", "source_ip", "destination_ip",
        "attack_type", "severity_level", "anomaly_score",
        "risk_score", "risk_level", "action_taken",
    ]

    if alerts_df.empty:
        empty_state("No events currently meet the suspicious threshold.", icon="shield")
    else:
        st.dataframe(
            format_table(alerts_df, display_columns),
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# INVESTIGATION
# ============================================================

elif page == "Investigation":

    page_header(
        "Investigation",
        "Build your own query",
        "Combine filters to narrow down a specific pattern of events",
    )

    help_box(
        "Set any of the filters below — leave a filter on <b>All</b> to ignore it. "
        "Filters combine together, so adding more narrows the results further."
    )

    with st.container(border=True):
        st.caption("NETWORK")
        col1, col2, col3 = st.columns(3)

        source_options = sorted(df["source_ip"].dropna().astype(str).unique().tolist())
        destination_options = sorted(df["destination_ip"].dropna().astype(str).unique().tolist())
        protocol_options = sorted(df["protocol"].dropna().astype(str).unique().tolist())

        selected_source = col1.selectbox("Source IP", ["All"] + source_options)
        selected_destination = col2.selectbox("Destination IP", ["All"] + destination_options)
        selected_protocol = col3.selectbox("Protocol", ["All"] + protocol_options)

        st.caption("THREAT")
        col1, col2, col3 = st.columns(3)

        attack_options = sorted(df["attack_type"].dropna().astype(str).unique().tolist())
        severity_options = sorted(df["severity_level"].dropna().astype(str).unique().tolist())
        network_options = sorted(df["network_segment"].dropna().astype(str).unique().tolist())

        selected_attack = col1.selectbox("Attack type", ["All"] + attack_options)
        selected_severity = col2.selectbox("Severity", ["All"] + severity_options)
        selected_network = col3.selectbox("Network segment", ["All"] + network_options)

        st.caption("CONNECTION")
        col1, col2 = st.columns(2)

        connection_options = sorted(df["connection_type"].dropna().astype(str).unique().tolist())

        selected_connection = col1.selectbox("Connection type", ["All"] + connection_options)
        selected_risk = col2.selectbox("Risk level", ["All"] + RISK_ORDER)

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
    risk_legend()

    display_columns = [
        "event_id", "Timestamp", "source_ip", "destination_ip", "protocol",
        "attack_type", "severity_level", "anomaly_score",
        "risk_score", "risk_level", "action_taken",
    ]

    if filtered.empty:
        empty_state("No events match the current filters. Try widening your criteria.", icon="search")
    else:
        st.dataframe(
            format_table(filtered, display_columns),
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# EVENT DETAIL
# ============================================================

elif page == "Event detail":

    page_header(
        "Event detail",
        "Full context, one event at a time",
        "Look up a single event to see its full context",
    )

    event_ids_numeric = pd.to_numeric(df["event_id"], errors="coerce")

    if event_ids_numeric.notna().all():
        min_id, max_id = int(event_ids_numeric.min()), int(event_ids_numeric.max())

        if "event_lookup_id" not in st.session_state:
            st.session_state.event_lookup_id = min_id

        top_risk = df.sort_values("risk_score", ascending=False).head(15)
        quick_options = ["—"] + top_risk["event_id"].astype(str).tolist()

        c1, c2 = st.columns([1, 2])
        quick_pick = c1.selectbox("Jump to a high-risk event", quick_options)
        if quick_pick != "—":
            st.session_state.event_lookup_id = int(quick_pick)

        c2.number_input(
            "Or enter an Event ID directly",
            min_value=min_id,
            max_value=max_id,
            step=1,
            key="event_lookup_id",
        )
        selected_event = str(st.session_state.event_lookup_id)
    else:
        event_ids = df["event_id"].dropna().astype(str).tolist()
        selected_event = st.selectbox("Event ID", event_ids)

    event = df[df["event_id"].astype(str) == selected_event]

    if not event.empty:
        row = event.iloc[0]

        section_header("Risk assessment")

        c1, c2, c3 = st.columns(3)
        kpi_card(c1, "Risk score", int(row["risk_score"]), "Out of 100",
                  accent=True, icon="alert", icon_color=_risk_color(row["risk_level"]))
        c2.markdown(
            '<div class="kpi-card"><div class="kpi-top-row">'
            '<div class="kpi-label">Risk level</div></div>'
            f'<div style="margin-top:2px;">{risk_badge(row["risk_level"])}</div></div>',
            unsafe_allow_html=True,
        )
        kpi_card(c3, "Suspicious", "Yes" if row["is_suspicious"] else "No", "Score 30 or higher",
                  icon="search", icon_color=COLORS["accent"])

        section_header("Event information")

        yes_no = lambda v: "Yes" if v == 1 else "No"
        timestamp_display = pd.to_datetime(row["Timestamp"]).strftime("%Y-%m-%d %H:%M:%S")

        details = {
            "Event ID": row["event_id"],
            "Timestamp": timestamp_display,
            "Source IP": row["source_ip"],
            "Destination IP": row["destination_ip"],
            "Protocol": row["protocol"],
            "Attack type": row["attack_type"],
            "Attack signature": row["attack_signature"],
            "Severity level": row["severity_level"],
            "Anomaly score": round(float(row["anomaly_score"]), 1),
            "Network segment": row["network_segment"],
            "Connection type": row["connection_type"],
            "Packet length": row["packet_length"],
            "Malware indicator": yes_no(row["malware_indicator"]),
            "IDS/IPS alert": yes_no(row["ids_ips_alert_present"]),
            "Firewall log": yes_no(row["firewall_log_present"]),
            "Alert triggered": yes_no(row["alert_triggered"]),
            "Proxy present": yes_no(row["proxy_present"]),
            "Action taken": row["action_taken"],
        }

        details_df = pd.DataFrame(details.items(), columns=["Field", "Value"])

        st.dataframe(details_df, use_container_width=True, hide_index=True)

        help_box("Investigation focus: what happened, and how concerning is this event?")
