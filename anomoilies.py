import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
from sklearn.ensemble import IsolationForest
from elasticsearch import Elasticsearch
import eland as ed
from datetime import datetime, timedelta
import json
import streamlit as st
import time  # For the refresh button

# --- Elasticsearch Connection ---
es_client = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("ashokp", "ashok123"),
    verify_certs=False,
    request_timeout=60,
    retry_on_timeout=True,
    max_retries=3,
    headers={'Accept': 'application/vnd.elasticsearch+json;compatible-with=8'}
)

# --- Anomaly Detection Functions (as before) ---
def detect_anomalies():
    stream_name_logs = "logs-generic.otel-default"
    df_logs = ed.DataFrame(es_client, es_index_pattern=stream_name_logs)
    query = {
        "range": {
            "@timestamp": {
                "gte": "now-24h",
                "lte": "now"
            }
        }
    }
    recent_logs = df_logs.es_query(query)
    logs_pd = ed.eland_to_pandas(recent_logs[["@timestamp", "attributes.service_name",
                                              "attributes.status_code", "attributes.emp_id", "attributes.asctime"]])
    logs_pd["attributes.asctime"] = pd.to_datetime(logs_pd["attributes.asctime"], errors="coerce")
    logs_pd["timestamp"] = pd.to_datetime(logs_pd["@timestamp"])
    logs_pd["time_window"] = logs_pd["timestamp"].dt.floor("5min")
    request_counts = logs_pd.groupby(["time_window", "attributes.service_name", "attributes.status_code"]).size().reset_index(name="count")
    pivot_df = request_counts.pivot_table(
        index=["time_window", "attributes.service_name"],
        columns=["attributes.status_code"],
        values="count",
        fill_value=0
    ).reset_index()
    for col in pivot_df.columns:
        if col not in ["time_window", "attributes.service_name"] and col not in pivot_df.columns:
            pivot_df[col] = 0
    features = [col for col in pivot_df.columns if col not in ["time_window", "attributes.service_name"]]
    X = pivot_df[features].values
    model = IsolationForest(contamination=0.05, random_state=0)
    pivot_df["anomaly"] = model.fit_predict(X)
    pivot_df["anomaly_score"] = model.decision_function(X)
    pivot_df["anomaly_score_inverted"] = -pivot_df["anomaly_score"]
    anomalies = pivot_df[pivot_df["anomaly"] == -1]
    anomalous_windows = anomalies[["time_window", "attributes.service_name", "anomaly_score_inverted"]]
    anomalous_logs = pd.merge(logs_pd, anomalous_windows, on=["time_window", "attributes.service_name"], how="inner")
    print(f"Detected {len(anomalies)} anomalies")
    return pivot_df, anomalous_logs, logs_pd

def plot_anomalies(pivot_df, anomalous_logs, services):
    fig, ax = plt.subplots(figsize=(14, 6))
    for service in services:
        service_data = pivot_df[pivot_df["attributes.service_name"] == service].sort_values(by='time_window')
        ax.plot(service_data["time_window"], service_data["anomaly_score_inverted"], label=service, alpha=0.7)
    ax.scatter(anomalous_logs["time_window"], anomalous_logs["anomaly_score_inverted"],
               color='red', s=50, label="Anomalies")
    ax.axhline(y=0, color='r', linestyle='-', alpha=0.3)
    ax.set_xlabel("Time Window")
    ax.set_ylabel("Anomaly Score (Inverted)")
    ax.set_title("Anomaly Scores Over Time")
    ax.legend()
    fig.tight_layout()
    return fig

def create_service_graph(logs_pd):
    G = nx.DiGraph()
    service_interactions = logs_pd.groupby(["attributes.service_name", "attributes.status_code"]).size().reset_index()
    services = logs_pd["attributes.service_name"].unique()
    for service in services:
        G.add_node(service)
    for _, row in service_interactions.iterrows():
        source = row["attributes.service_name"]
        status = row["attributes.status_code"]
        count = row[0]
        if status in [401, 503]:
            G.add_edge(source, f"Error ({status})", weight=count, color='red')
        else:
            G.add_edge(source, f"Success ({status})", weight=count, color='green')
    fig, ax = plt.subplots(figsize=(12, 8))
    pos = nx.spring_layout(G)
    edge_colors = [G[u][v]['color'] for u, v in G.edges()]
    nx.draw(G, pos, with_labels=True, node_color='skyblue',
            node_size=1500, edge_color=edge_colors, width=2, font_size=10, ax=ax)
    ax.set_title("Service Interaction Graph")
    fig.tight_layout()
    return fig

# --- Functions to Fetch and Display Metrics ---
def fetch_metrics_data():
    stream_name_metrics = "metrics-generic.otel-default"
    df_metrics = ed.DataFrame(es_client, es_index_pattern=stream_name_metrics)
    query = {
        "range": {
            "@timestamp": {
                "gte": "now-24h",
                "lte": "now"
            }
        }
    }
    recent_metrics = df_metrics.es_query(query)
    metrics_pd = ed.eland_to_pandas(recent_metrics)
    return metrics_pd

def display_metrics(metrics_pd):
    st.subheader("Metrics Data")
    if not metrics_pd.empty:
        if "timestamp" in metrics_pd.columns:
            metrics_pd["timestamp"] = pd.to_datetime(metrics_pd["@timestamp"])
            if "attributes.service_name" in metrics_pd.columns:
                services = metrics_pd["attributes.service_name"].unique()
                fig_metrics, ax_metrics = plt.subplots(figsize=(14, 6))
                for service in services:
                    service_metrics = metrics_pd[metrics_pd["attributes.service_name"] == service].sort_values(by="timestamp")
                    if 'attributes.cpu.usage' in service_metrics.columns:
                        ax_metrics.plot(service_metrics["timestamp"], service_metrics['attributes.cpu.usage'], label=service)
                ax_metrics.set_xlabel("Timestamp")
                ax_metrics.set_ylabel("CPU Usage (%)")
                ax_metrics.set_title("CPU Usage Over Time")
                ax_metrics.legend()
                fig_metrics.tight_layout()
                st.pyplot(fig_metrics)
            else:
                st.warning("Service name information not found in metrics data.")
        else:
            st.warning("Timestamp information not found in metrics data.")
        st.dataframe(metrics_pd)
    else:
        st.info("No metrics data available.")

# --- Functions to Fetch and Display Traces ---
def fetch_traces_data():
    stream_name_traces = "traces-generic.otel-default"
    df_traces = ed.DataFrame(es_client, es_index_pattern=stream_name_traces)
    query = {
        "range": {
            "@timestamp": {
                "gte": "now-24h",
                "lte": "now"
            }
        }
    }
    recent_traces = df_traces.es_query(query)
    traces_pd = ed.eland_to_pandas(recent_traces)
    return traces_pd

def display_traces(traces_pd):
    st.subheader("Traces Data")
    if not traces_pd.empty:
        st.dataframe(traces_pd)
        st.info("Visualizing traces effectively often requires specific tools. The raw data can be explored here.")
    else:
        st.info("No traces data available.")

# --- SLI and SLO Calculation and Visualization ---
def calculate_sli(logs_pd):
    if logs_pd is not None and not logs_pd.empty:
        successful_requests = logs_pd[logs_pd["attributes.status_code"].astype(str).str.startswith('2')].shape[0]
        total_requests = logs_pd.shape[0]
        if total_requests > 0:
            sli = (successful_requests / total_requests) * 100
            return sli
        else:
            return 0.0
    else:
        return None

def display_sli(sli_value):
    st.subheader("Service Level Indicator (SLI)")
    if sli_value is not None:
        st.metric("Successful HTTP Request Rate", f"{sli_value:.2f}%")
    else:
        st.info("No log data available to calculate SLI.")

def calculate_slo(logs_pd):
    if logs_pd is not None and not logs_pd.empty:
        time_threshold = datetime.now(tz=logs_pd["timestamp"].iloc[0].tzinfo) - timedelta(days=2)
        recent_logs = logs_pd[logs_pd["timestamp"] >= time_threshold]
        successful_requests = recent_logs[recent_logs["attributes.status_code"].astype(str).str.startswith('2')].shape[0]
        total_requests = recent_logs.shape[0]
        if total_requests > 0:
            slo_achieved = (successful_requests / total_requests) * 100 >= 99.95
            success_rate = (successful_requests / total_requests) * 100
            return slo_achieved, success_rate
        else:
            return False, 0.0
    else:
        return None, None

def display_slo(slo_achieved, success_rate):
    st.subheader("Service Level Objective (SLO)")
    if slo_achieved is not None:
        if slo_achieved:
            st.success(f"SLO Met: 99.95% success rate achieved ({success_rate:.2f}%) over the last 2 days.")
        else:
            st.error(f"SLO Not Met: Current success rate is {success_rate:.2f}% over the last 2 days (Target: 99.95%).")
    else:
        st.info("No log data available to calculate SLO.")

# --- Streamlit App with Tabs ---
# --- Streamlit App with Tabs ---

st.title("Real-time Anomaly Detection and Observability Dashboard")

tabs = st.tabs(["Anomaly Detection", "SLI", "SLO"])

with tabs[0]:
    st.header("Anomaly Detection")
    if st.button("Refresh Anomaly Data"):
        with st.spinner("Fetching and analyzing latest anomaly data..."):
            pivot_df, anomalous_logs, logs_pd_for_anomalies = detect_anomalies()
            services = logs_pd_for_anomalies["attributes.service_name"].unique()
            anomaly_plot = plot_anomalies(pivot_df, anomalous_logs, services)
            st.pyplot(anomaly_plot)
            st.success("Latest anomalies detected and displayed!")

    if st.checkbox("Show Service Interaction Graph", key="anomaly_graph"):
        with st.spinner("Generating service interaction graph..."):
            _, _, logs_pd_for_graph = detect_anomalies()  # Re-run to get fresh logs_pd
            service_graph = create_service_graph(logs_pd_for_graph)
            st.pyplot(service_graph)
    else:
        st.info("Click 'Refresh Anomaly Data' to update the anomaly detection and optionally view the service interaction graph.")

with tabs[1]:
    st.header("Service Level Indicator (SLI)")
    if st.button("Calculate Latest SLI"):
        with st.spinner("Calculating SLI..."):
            _, _, logs_pd_for_sli = detect_anomalies()  # Re-run to get fresh logs_pd
            if logs_pd_for_sli is not None:
                sli_value = calculate_sli(logs_pd_for_sli)
                st.metric("Successful HTTP Request Rate", f"{sli_value:.2f}%")

                # Plot SLI over time
                logs_pd_for_sli["timestamp"] = pd.to_datetime(logs_pd_for_sli["@timestamp"])
                logs_pd_for_sli["is_successful"] = logs_pd_for_sli["attributes.status_code"].astype(str).str.startswith('2')
                sli_over_time = logs_pd_for_sli.groupby(logs_pd_for_sli["timestamp"].dt.floor("1H"))["is_successful"].mean() * 100

                fig, ax = plt.subplots(figsize=(14, 6))
                sli_over_time.plot(ax=ax, marker='o', color='blue', label="SLI (%)")
                ax.axhline(y=99.95, color='green', linestyle='--', label="SLO Target (99.95%)")
                ax.set_xlabel("Time")
                ax.set_ylabel("SLI (%)")
                ax.set_title("SLI Over Time")
                ax.legend()
                st.pyplot(fig)

                st.success("SLI calculated and displayed!")
            else:
                st.warning("No log data available to calculate SLI.")
    else:
        st.info("Click 'Calculate Latest SLI' to see the current successful HTTP request rate.")

with tabs[2]:
    st.header("Service Level Objective (SLO)")
    if st.button("Check Latest SLO"):
        with st.spinner("Checking SLO status..."):
            _, _, logs_pd_for_slo = detect_anomalies()  # Re-run to get fresh logs_pd
            if logs_pd_for_slo is not None:
                slo_achieved, success_rate = calculate_slo(logs_pd_for_slo)
                display_slo(slo_achieved, success_rate)
                st.success("SLO status checked and displayed!")
            else:
                st.warning("No log data available to check SLO status.")
    else:
        st.info("Click 'Check Latest SLO' to see the current SLO status based on the last 2 days of logs.")