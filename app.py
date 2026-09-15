import os
import streamlit as st
import pandas as pd
import duckdb
import plotly.express as px


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Cybersecurity Threat Monitoring",
    page_icon="🛡️",
    layout="wide"
)


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

# Columns each table needs to have for the query below to work.
# Used to give a precise error message instead of a bare DuckDB
# BinderException / KeyError if the parquet schema drifts.
REQUIRED_COLUMNS = {
    "fact": [
        "event_id", "Timestamp", "attack_id", "source_ip_id",
        "destination_ip_id", "network_id", "time_id",
        "Packet Length", "Anomaly Scores", "Severity Level",
        "Action Taken", "malware_indicator", "alert_triggered",
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

    missing = [
        col for col in REQUIRED_COLUMNS[label] if col not in df.columns
    ]

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
        f.Timestamp,

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

        f."Packet Length" AS packet_length,
        f."Anomaly Scores" AS anomaly_score,
        f."Severity Level" AS severity_level,
        f."Action Taken" AS action_taken,

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
        (
            df["severity_level"]
            .astype(str)
            .str.lower()
            .eq("high")
        ).astype(int) * 30

        +

        (df["anomaly_score"] > 80).astype(int) * 25

        +

        (df["malware_indicator"] == 1).astype(int) * 20

        +

        (df["ids_ips_alert_present"] == 1).astype(int) * 15

        +

        (df["alert_triggered"] == 1).astype(int) * 10
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

    df["risk_level"] = df["risk_score"].apply(
        assign_risk_level
    )

    df["is_suspicious"] = (
        df["risk_score"] >= 30
    )

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

    st.stop()


# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

st.sidebar.title("🛡️ Threat Monitoring")

page = st.sidebar.radio(
    "Navigation",
    [
        "📊 Dashboard",
        "🚨 Threat Alerts",
        "🔎 Threat Investigation",
        "📋 Event Details"
    ]
)


# ============================================================
# DASHBOARD
# ============================================================

if page == "📊 Dashboard":

    st.title("🛡️ Cybersecurity Threat Monitoring")

    st.write(
        "Cybersecurity Threat Monitoring & Log Analytics"
    )

    # --------------------------------------------------------
    # KPI
    # --------------------------------------------------------

    total_events = len(df)

    high_risk_events = df[
        df["risk_level"].isin(
            ["Critical", "High"]
        )
    ]

    high_risk = len(high_risk_events)

    malware = (
        df["malware_indicator"] == 1
    ).sum()

    alerts = (
        df["alert_triggered"] == 1
    ).sum()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Events",
        f"{total_events:,}"
    )

    col2.metric(
        "High Risk",
        f"{high_risk:,}"
    )

    col3.metric(
        "Malware Indicators",
        f"{malware:,}"
    )

    col4.metric(
        "Alerts",
        f"{alerts:,}"
    )

    st.divider()

    # --------------------------------------------------------
    # EVENTS OVER TIME
    # --------------------------------------------------------

    daily_events = (
        df.groupby("event_date")
        .size()
        .reset_index(name="events")
    )

    fig = px.line(
        daily_events,
        x="event_date",
        y="events",
        title="Events Over Time"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # --------------------------------------------------------
    # ATTACK TYPE
    # --------------------------------------------------------

    col1, col2 = st.columns(2)

    attack_counts = (
        df["attack_type"]
        .value_counts()
        .reset_index()
    )

    attack_counts.columns = [
        "attack_type",
        "events"
    ]

    fig_attack = px.bar(
        attack_counts,
        x="attack_type",
        y="events",
        title="Attack Type Distribution"
    )

    col1.plotly_chart(
        fig_attack,
        use_container_width=True
    )

    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    severity_counts = (
        df["severity_level"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = [
        "severity",
        "events"
    ]

    fig_severity = px.bar(
        severity_counts,
        x="severity",
        y="events",
        title="Severity Level"
    )

    col2.plotly_chart(
        fig_severity,
        use_container_width=True
    )

    # --------------------------------------------------------
    # PROTOCOL
    # --------------------------------------------------------

    protocol_counts = (
        df["protocol"]
        .value_counts()
        .reset_index()
    )

    protocol_counts.columns = [
        "protocol",
        "events"
    ]

    fig_protocol = px.pie(
        protocol_counts,
        names="protocol",
        values="events",
        title="Protocol Distribution"
    )

    st.plotly_chart(
        fig_protocol,
        use_container_width=True
    )

    # --------------------------------------------------------
    # ACTION TAKEN
    # --------------------------------------------------------

    action_counts = (
        df["action_taken"]
        .value_counts()
        .reset_index()
    )

    action_counts.columns = [
        "action",
        "events"
    ]

    fig_action = px.bar(
        action_counts,
        x="action",
        y="events",
        title="Action Taken"
    )

    st.plotly_chart(
        fig_action,
        use_container_width=True
    )


# ============================================================
# THREAT ALERTS
# ============================================================

elif page == "🚨 Threat Alerts":

    st.title("🚨 Threat Alerts")

    st.write(
        "Suspicious events sorted by risk score."
    )

    alerts_df = df[
        df["is_suspicious"]
    ].copy()

    alerts_df = alerts_df.sort_values(
        by=["risk_score", "Timestamp"],
        ascending=[False, False]
    )

    # --------------------------------------------------------
    # ALERT SUMMARY
    # --------------------------------------------------------

    critical_count = (
        alerts_df["risk_level"] == "Critical"
    ).sum()

    high_count = (
        alerts_df["risk_level"] == "High"
    ).sum()

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Suspicious Events",
        f"{len(alerts_df):,}"
    )

    col2.metric(
        "Critical",
        f"{critical_count:,}"
    )

    col3.metric(
        "High",
        f"{high_count:,}"
    )

    st.divider()

    # --------------------------------------------------------
    # ALERT TABLE
    # --------------------------------------------------------

    display_columns = [
        "event_id",
        "Timestamp",
        "source_ip",
        "destination_ip",
        "attack_type",
        "severity_level",
        "anomaly_score",
        "risk_score",
        "risk_level",
        "action_taken"
    ]

    st.dataframe(
        alerts_df[display_columns],
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# THREAT INVESTIGATION
# ============================================================

elif page == "🔎 Threat Investigation":

    st.title("🔎 Threat Investigation")

    st.write(
        "Use filters to investigate security events."
    )

    # --------------------------------------------------------
    # FILTER 1
    # --------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    source_options = sorted(
        df["source_ip"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    destination_options = sorted(
        df["destination_ip"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    protocol_options = sorted(
        df["protocol"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    selected_source = col1.selectbox(
        "Source IP",
        ["All"] + source_options
    )

    selected_destination = col2.selectbox(
        "Destination IP",
        ["All"] + destination_options
    )

    selected_protocol = col3.selectbox(
        "Protocol",
        ["All"] + protocol_options
    )

    # --------------------------------------------------------
    # FILTER 2
    # --------------------------------------------------------

    col1, col2, col3 = st.columns(3)

    attack_options = sorted(
        df["attack_type"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    severity_options = sorted(
        df["severity_level"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    network_options = sorted(
        df["network_segment"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    selected_attack = col1.selectbox(
        "Attack Type",
        ["All"] + attack_options
    )

    selected_severity = col2.selectbox(
        "Severity",
        ["All"] + severity_options
    )

    selected_network = col3.selectbox(
        "Network Segment",
        ["All"] + network_options
    )

    # --------------------------------------------------------
    # FILTER 3
    # --------------------------------------------------------

    col1, col2 = st.columns(2)

    connection_options = sorted(
        df["connection_type"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    selected_connection = col1.selectbox(
        "Connection Type",
        ["All"] + connection_options
    )

    selected_risk = col2.selectbox(
        "Risk Level",
        [
            "All",
            "Critical",
            "High",
            "Medium",
            "Low"
        ]
    )

    # --------------------------------------------------------
    # APPLY FILTERS
    # --------------------------------------------------------

    filtered = df.copy()

    if selected_source != "All":

        filtered = filtered[
            filtered["source_ip"].astype(str)
            == selected_source
        ]

    if selected_destination != "All":

        filtered = filtered[
            filtered["destination_ip"].astype(str)
            == selected_destination
        ]

    if selected_protocol != "All":

        filtered = filtered[
            filtered["protocol"].astype(str)
            == selected_protocol
        ]

    if selected_attack != "All":

        filtered = filtered[
            filtered["attack_type"].astype(str)
            == selected_attack
        ]

    if selected_severity != "All":

        filtered = filtered[
            filtered["severity_level"].astype(str)
            == selected_severity
        ]

    if selected_network != "All":

        filtered = filtered[
            filtered["network_segment"].astype(str)
            == selected_network
        ]

    if selected_connection != "All":

        filtered = filtered[
            filtered["connection_type"].astype(str)
            == selected_connection
        ]

    if selected_risk != "All":

        filtered = filtered[
            filtered["risk_level"]
            == selected_risk
        ]

    filtered = filtered.sort_values(
        by=["risk_score", "Timestamp"],
        ascending=[False, False]
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    st.divider()

    st.metric(
        "Matching Events",
        f"{len(filtered):,}"
    )

    display_columns = [
        "event_id",
        "Timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "attack_type",
        "severity_level",
        "anomaly_score",
        "risk_score",
        "risk_level",
        "action_taken"
    ]

    st.dataframe(
        filtered[display_columns],
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# EVENT DETAILS
# ============================================================

elif page == "📋 Event Details":

    st.title("📋 Event Details")

    st.write(
        "Select an event to investigate its details."
    )

    event_ids = (
        df["event_id"]
        .dropna()
        .astype(str)
        .tolist()
    )

    selected_event = st.selectbox(
        "Event ID",
        event_ids
    )

    event = df[
        df["event_id"].astype(str)
        == selected_event
    ]

    if not event.empty:

        row = event.iloc[0]

        # ----------------------------------------------------
        # RISK ASSESSMENT
        # ----------------------------------------------------

        st.subheader("Risk Assessment")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Risk Score",
            int(row["risk_score"])
        )

        col2.metric(
            "Risk Level",
            row["risk_level"]
        )

        col3.metric(
            "Suspicious",
            "Yes"
            if row["is_suspicious"]
            else "No"
        )

        st.divider()

        # ----------------------------------------------------
        # EVENT DETAILS
        # ----------------------------------------------------

        st.subheader("Event Information")

        details = {
            "Event ID": row["event_id"],
            "Timestamp": row["Timestamp"],
            "Source IP": row["source_ip"],
            "Destination IP": row["destination_ip"],
            "Protocol": row["protocol"],
            "Attack Type": row["attack_type"],
            "Attack Signature": row["attack_signature"],
            "Severity Level": row["severity_level"],
            "Anomaly Score": row["anomaly_score"],
            "Network Segment": row["network_segment"],
            "Connection Type": row["connection_type"],
            "Packet Length": row["packet_length"],
            "Malware Indicator": row["malware_indicator"],
            "IDS/IPS Alert": row["ids_ips_alert_present"],
            "Firewall Log": row["firewall_log_present"],
            "Alert Triggered": row["alert_triggered"],
            "Proxy Present": row["proxy_present"],
            "Action Taken": row["action_taken"]
        }

        details_df = pd.DataFrame(
            details.items(),
            columns=["Field", "Value"]
        )

        st.dataframe(
            details_df,
            use_container_width=True,
            hide_index=True
        )

        st.info(
            "Investigation focus: what happened and "
            "how concerning is this event?"
        )
