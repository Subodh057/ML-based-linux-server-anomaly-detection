import streamlit as st
import pandas as pd
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))
from model import detect_anomaly


DATA_PATH = "data/live_data.csv"

st.set_page_config(
    page_title="ZeroWatch LLM Dashboard",
    layout="wide"
)

st.title("ZeroWatch LLM | Server Anomaly Dashboard")
st.caption("Real-time Linux server anomaly detection using local baseline model")

if not os.path.exists(DATA_PATH):
    st.error("live_data.csv not found. Run collector.py first.")
    st.stop()

df = pd.read_csv(DATA_PATH)

FEATURES = [
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "running_process_count",
    "network_connections",
    "bytes_sent",
    "bytes_recv",
    "failed_login_count",
    "successful_login_count",
    "root_login_count",
    "unique_ip_count"
]

results = []

for _, row in df.iterrows():
    data = row[FEATURES].to_dict()
    result = detect_anomaly(data)

    results.append({
        "status": result.get("status", "unknown"),
        "risk": result.get("risk", "unknown"),
        "anomaly_score": result.get("anomaly_score", 0)
    })

result_df = pd.DataFrame(results)
df = pd.concat([df, result_df], axis=1)

total_events = len(df)
normal_events = len(df[df["status"] == "normal"])
anomaly_events = len(df[df["status"] == "anomaly"])
latest_risk = df.iloc[-1]["risk"]

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total_events)
col2.metric("Normal Events", normal_events)
col3.metric("Anomalies Detected", anomaly_events)
col4.metric("Current Risk", latest_risk.upper())

st.divider()

col5, col6 = st.columns(2)

with col5:
    st.subheader("CPU Usage Over Time")
    st.line_chart(df["cpu_usage"])

with col6:
    st.subheader("Memory Usage Over Time")
    st.line_chart(df["memory_usage"])

col7, col8 = st.columns(2)

with col7:
    st.subheader("Network Connections")
    st.line_chart(df["network_connections"])

with col8:
    st.subheader("Anomaly Score")
    st.line_chart(df["anomaly_score"])

st.divider()

st.subheader("Risk Distribution")
risk_count = df["risk"].value_counts()
st.bar_chart(risk_count)

st.subheader("Recent Server Events")
st.dataframe(
    df[
        [
            "timestamp",
            "hostname",
            "cpu_usage",
            "memory_usage",
            "network_connections",
            "failed_login_count",
            "status",
            "risk",
            "anomaly_score"
        ]
    ].tail(20),
    use_container_width=True
)

st.subheader("Latest Event Analysis")

latest = df.iloc[-1]

if latest["status"] == "anomaly":
    st.error("Anomaly detected in the latest server event.")
    st.write("Possible reason: Current server behavior is different from the trained local baseline.")
    st.write("Recommended action: Check CPU usage, network connections, login attempts, and running processes.")
else:
    st.success("Latest server event appears normal.")
