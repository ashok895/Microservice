import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
from sklearn.ensemble import IsolationForest
from elasticsearch import Elasticsearch, helpers # Import helpers for bulk operations
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

# --- Anomaly Detection Functions ---
def detect_anomalies():
    """
    Detects security anomalies based on request counts and status codes.
    Returns pivot_df, anomalous_logs, and the raw logs_pd.
    """
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
                                              "attributes.status_code", "attributes.emp_id", "attributes.asctime", "attributes.latency"]])
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
    # Ensure all possible status_code columns exist, initializing with 0 if not
    # This loop assumes a static set of expected status codes if not found in data
    # A more robust solution might dynamically check unique status codes or use a predefined list.
    # For simplicity, we'll keep the current approach, but be aware it might not catch all cases.
    # E.g., if '200' is always present, but '400' might not be.
    # The original code's loop iterates over 'pivot_df.columns' in the check, which is self-defeating.
    # It should iterate over a *desired* set of status codes.
    # Let's fix this for robustness:
    all_possible_status_codes = [200, 201, 204, 400, 401, 403, 404, 500, 502, 503] # Example list
    for code in all_possible_status_codes:
        if code not in pivot_df.columns:
            pivot_df[code] = 0

    features = [col for col in pivot_df.columns if col not in ["time_window", "attributes.service_name"]]
    X = pivot_df[features].values
    model = IsolationForest(contamination=0.05, random_state=0)
    pivot_df["anomaly"] = model.fit_predict(X)
    pivot_df["anomaly_score"] = model.decision_function(X)

    pivot_df["anomaly_score_inverted"] = -pivot_df["anomaly_score"]
    pivot_df["anomaly_score_normalized"] = pivot_df["anomaly_score_inverted"] - pivot_df["anomaly_score_inverted"].min()

    anomalies = pivot_df[pivot_df["anomaly"] == -1]
    anomalous_windows = anomalies[["time_window", "attributes.service_name", "anomaly_score_normalized"]]
    anomalous_logs = pd.merge(logs_pd, anomalous_windows, on=["time_window", "attributes.service_name"], how="inner")
    print(f"Detected {len(anomalies)} security anomalies")
    return pivot_df, anomalous_logs, logs_pd

def plot_anomalies(pivot_df, anomalous_logs, services):
    fig, ax = plt.subplots(figsize=(14, 6))
    for service in services:
        service_data = pivot_df[pivot_df["attributes.service_name"] == service].sort_values(by='time_window')
        ax.plot(service_data["time_window"], service_data["anomaly_score_normalized"], label=service, alpha=0.7)
    # Filter anomalous_logs to only include actual anomalies for plotting
    plot_anomalies_data = anomalous_logs[anomalous_logs["anomaly_score_normalized"].notna()]
    ax.scatter(plot_anomalies_data["time_window"], plot_anomalies_data["anomaly_score_normalized"],
               color='red', s=50, label="Security Anomalies")
    ax.set_xlabel("Time Window")
    ax.set_ylabel("Anomaly Score (Normalized)")
    ax.set_title("Security Anomaly Scores Over Time")
    ax.legend()
    fig.tight_layout()
    return fig

def create_service_graph(logs_pd):
    G = nx.DiGraph()
    # For service graph, we care about actual interactions, not just status codes.
    # This might need refinement based on how your services actually call each other.
    # For now, we'll use the existing logic of logging service and its status.
    service_interactions = logs_pd.groupby(["attributes.service_name", "attributes.status_code"]).size().reset_index(name="count")
    services = logs_pd["attributes.service_name"].unique()

    for service in services:
        G.add_node(service)

    # Simplified representation: edges from service to a generic 'Success' or 'Error' state
    for _, row in service_interactions.iterrows():
        source = row["attributes.service_name"]
        status = row["attributes.status_code"]
        count = row["count"] # Use the named column 'count'

        if str(status).startswith(('4', '5')): # Check for 4xx or 5xx errors
            G.add_edge(source, f"Error ({status})", weight=count, color='red')
        elif str(status).startswith('2'): # Check for 2xx success
            G.add_edge(source, f"Success ({status})", weight=count, color='green')
        else:
            # Handle other status codes if necessary or ignore
            pass

    fig, ax = plt.subplots(figsize=(12, 8))
    pos = nx.spring_layout(G, k=0.8) # Adjust k for better spacing
    edge_colors = [G[u][v]['color'] for u, v in G.edges()]

    # Draw nodes and edges
    nx.draw_networkx_nodes(G, pos, node_color='skyblue', node_size=1500, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=10, ax=ax)
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors, width=2, alpha=0.7, ax=ax)

    # Optional: Draw edge labels (weights)
    # edge_labels = nx.get_edge_attributes(G, 'weight')
    # nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='blue', ax=ax)

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

# --- Function to Fetch Defects from Elasticsearch ---
def fetch_defects_data():
    index_name = "jira_defects"
    query = {"query": {"match_all": {}}}
    try:
        response = es_client.search(index=index_name, body=query, size=1000)
        defects = [doc["_source"] for doc in response["hits"]["hits"]]
        defects_pd = pd.DataFrame(defects)
        return defects_pd
    except Exception as e:
        st.error(f"Error fetching defects: {e}")
        return pd.DataFrame()

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
        # Ensure status_code is treated as string for .startswith()
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
        # Get timezone from the first timestamp for proper comparison
        if not logs_pd["timestamp"].empty:
            tz = logs_pd["timestamp"].iloc[0].tzinfo
            time_threshold = datetime.now(tz=tz) - timedelta(days=2)
        else:
            # Fallback if no timestamps, though logs_pd.empty should catch this
            return None, None

        recent_logs = logs_pd[logs_pd["timestamp"] >= time_threshold]
        successful_requests = recent_logs[recent_logs["attributes.status_code"].astype(str).str.startswith('2')].shape[0]
        total_requests = recent_logs.shape[0]
        if total_requests > 0:
            success_rate = (successful_requests / total_requests) * 100
            slo_achieved = success_rate >= 99.95
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

# --- Functions for Performance Anomaly Detection ---
def detect_performance_anomalies():
    """
    Detects performance anomalies based on latency metrics from logs.
    Returns latency_summary_df, performance_anomalies_df, and the raw logs_pd.
    """
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
    logs_pd = ed.eland_to_pandas(recent_logs[["@timestamp", "attributes.service_name", "attributes.latency"]])
    logs_pd["timestamp"] = pd.to_datetime(logs_pd["@timestamp"])
    logs_pd["time_window"] = logs_pd["timestamp"].dt.floor("5min")

    # Convert latency to numeric (seconds)
    logs_pd['attributes.latency_numeric'] = pd.to_numeric(
        logs_pd['attributes.latency'].astype(str).str.replace(' seconds', '', regex=False),
        errors='coerce'
    )

    # Drop rows where latency couldn't be converted
    logs_pd.dropna(subset=['attributes.latency_numeric'], inplace=True)

    if logs_pd.empty:
        st.info("No valid latency data found for performance anomaly detection.")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    # Calculate 95th percentile latency for each time window and service
    latency_summary = logs_pd.groupby(["time_window", "attributes.service_name"])['attributes.latency_numeric'].quantile(0.95).reset_index(name="p95_latency")

    # Apply Isolation Forest for anomaly detection on p95_latency
    model = IsolationForest(contamination=0.05, random_state=0) # Contamination can be tuned
    latency_summary["anomaly"] = model.fit_predict(latency_summary[["p95_latency"]])
    latency_summary["anomaly_score"] = model.decision_function(latency_summary[["p95_latency"]])

    # Normalize anomaly score (higher score means more anomalous)
    latency_summary["anomaly_score_inverted"] = -latency_summary["anomaly_score"]
    latency_summary["anomaly_score_normalized"] = latency_summary["anomaly_score_inverted"] - latency_summary["anomaly_score_inverted"].min()

    performance_anomalies = latency_summary[latency_summary["anomaly"] == -1]
    print(f"Detected {len(performance_anomalies)} performance anomalies")

    # Merge original logs with anomaly info to get full details for export
    anomalous_performance_logs = pd.merge(
        logs_pd,
        performance_anomalies[['time_window', 'attributes.service_name', 'anomaly_score_normalized']],
        on=['time_window', 'attributes.service_name'],
        how='inner'
    )
    return latency_summary, performance_anomalies, anomalous_performance_logs

def plot_performance_anomalies(latency_summary_df, performance_anomalies_df):
    fig, ax = plt.subplots(figsize=(14, 6))
    services = latency_summary_df["attributes.service_name"].unique()
    for service in services:
        service_data = latency_summary_df[latency_summary_df["attributes.service_name"] == service].sort_values(by='time_window')
        ax.plot(service_data["time_window"], service_data["p95_latency"], label=f"{service} P95 Latency", alpha=0.7)

    # Plot detected anomalies
    if not performance_anomalies_df.empty:
        ax.scatter(performance_anomalies_df["time_window"], performance_anomalies_df["p95_latency"],
                   color='red', s=100, marker='X', label="Performance Anomaly (P95 Latency)")

    ax.set_xlabel("Time Window")
    ax.set_ylabel("95th Percentile Latency (seconds)")
    ax.set_title("95th Percentile Latency Over Time with Anomalies")
    ax.legend()
    fig.tight_layout()
    return fig

# --- Export to Elasticsearch Function ---
def export_anomalous_logs_to_es(df_anomalous_logs, index_name):
    """
    Exports a DataFrame of anomalous logs to a specified Elasticsearch index.
    """
    if df_anomalous_logs.empty:
        st.warning(f"No anomalous logs to export to '{index_name}'.")
        return False

    actions = []
    skipped_docs_count = 0 # To track documents that might be problematic

    for index, row in df_anomalous_logs.iterrows():
        doc = row.to_dict()

        # --- Debugging: Print problematic documents ---
        # It's good practice to ensure all values are JSON serializable and
        # in the expected format for Elasticsearch.
        processed_doc = {}
        has_error_in_doc = False
        for key, value in doc.items():
            try:
                if pd.isna(value): # Handle NaN values which are not JSON serializable
                    processed_doc[key] = None
                elif isinstance(value, pd.Timestamp):
                    processed_doc[key] = value.isoformat()
                elif isinstance(value, np.int64): # Convert numpy int64 to standard int
                    processed_doc[key] = int(value)
                elif isinstance(value, np.float64): # Convert numpy float64 to standard float
                    processed_doc[key] = float(value)
                else:
                    # Attempt to serialize to catch non-standard types before ES
                    json.dumps(value) # This will raise TypeError if not serializable
                    processed_doc[key] = value
            except TypeError as te:
                st.error(f"Serialization error for document ID {index}, field '{key}': {value} - {te}")
                st.error(f"Original row data: {row.to_dict()}")
                has_error_in_doc = True
                break # Stop processing this document if a serialization error occurs

        if has_error_in_doc:
            skipped_docs_count += 1
            continue # Skip this problematic document

        # Remove pandas-specific/temporary columns that might not be desired in ES
        # Ensure these are only removed AFTER potential type conversions if they were the source
        processed_doc.pop('timestamp', None) # Original timestamp might be renamed to @timestamp
        processed_doc.pop('time_window', None) # This is a calculated field
        processed_doc.pop('anomaly', None)
        processed_doc.pop('anomaly_score', None)
        processed_doc.pop('anomaly_score_inverted', None)
        processed_doc.pop('anomaly_score_normalized', None)

        if not processed_doc: # Check if the document source is empty after processing
            st.warning(f"Document ID {index} resulted in an empty source after processing. Skipping.")
            skipped_docs_count += 1
            continue

        actions.append({
            "_index": index_name,
            "_source": processed_doc
        })

    if not actions:
        st.warning(f"No valid documents were prepared for export to '{index_name}'. This might indicate an issue with data processing or all documents had serialization errors.")
        return False

    if skipped_docs_count > 0:
        st.warning(f"Skipped {skipped_docs_count} documents due to serialization issues or empty source.")

    try:
        # Create the index if it doesn't exist
        # Using ignore=400 is fine, it means 'ignore if already exists'
        es_client.indices.create(index=index_name, ignore=400)

        # Bulk insert
        st.info(f"Attempting to bulk insert {len(actions)} documents into '{index_name}'.")
        # Temporarily set raise_on_error=True to get a more specific error
        # during the first failure, then revert.
        success, failed = helpers.bulk(es_client, actions, raise_on_error=True) # <<< IMPORTANT CHANGE

        if success > 0:
            st.success(f"Successfully exported {success} anomalous logs to '{index_name}'.")
            if failed:
                st.warning(f"Failed to export {len(failed)} documents. Check Elasticsearch logs and the 'failed' list for details. First failed reason: {failed[0]['error'] if failed else 'N/A'}")
            return True
        else:
            # This block should ideally not be reached if raise_on_error=True
            st.error(f"Failed to export any logs to '{index_name}'. No successful operations.")
            if failed:
                st.error(f"Details of first failure: {failed[0]['error'] if failed else 'No error details available.'}")
            return False
    except Exception as e:
        # This will now catch the specific error from helpers.bulk if raise_on_error=True
        st.error(f"Error during Elasticsearch bulk export: {e}")
        # If it's a bulk error, it might have more details
        if hasattr(e, 'errors') and e.errors:
            st.error(f"First bulk error detail: {e.errors[0]}")
        return False
# --- Streamlit App with Tabs ---
st.title("Real-time Anomaly Detection and Observability Dashboard")

main_tabs = st.tabs(["Anomaly Detection", "Request Monitoring", "System Health Checks", "Defects"])

# --- Anomaly Detection Tab ---
with main_tabs[0]:
    st.header("Anomaly Detection")
    anomaly_detection_subtabs = st.tabs(["Security Anomalies", "Performance Anomalies"])

    # --- Security Anomalies Sub-tab (Original Anomaly Detection) ---
    with anomaly_detection_subtabs[0]:
        st.subheader("Security Anomalies (HTTP Status Codes)")
        # Initialize session state variables to store data for export
        if 'security_anomalous_logs_for_export' not in st.session_state:
            st.session_state.security_anomalous_logs_for_export = pd.DataFrame()

        if st.button("Refresh Security Anomaly Data", key="refresh_security_anomalies"):
            with st.spinner("Fetching and analyzing latest security anomaly data..."):
                pivot_df, anomalous_logs, logs_pd_for_anomalies = detect_anomalies()
                st.session_state.security_anomalous_logs_for_export = anomalous_logs # Store for export
                services = logs_pd_for_anomalies["attributes.service_name"].unique()
                if not pivot_df.empty and not anomalous_logs.empty:
                    anomaly_plot = plot_anomalies(pivot_df, anomalous_logs, services)
                    st.pyplot(anomaly_plot)
                    st.subheader("Detected Security Anomalies:")
                    st.dataframe(anomalous_logs[["@timestamp", "attributes.service_name", "attributes.status_code", "anomaly_score_normalized"]])
                    st.success("Latest security anomalies detected and displayed!")
                else:
                    st.info("No security anomalies detected in the last 24 hours.")

        if st.checkbox("Show Service Interaction Graph", key="security_anomaly_graph"):
            with st.spinner("Generating service interaction graph..."):
                # Use logs_pd from detect_anomalies if available, or fetch fresh
                if 'logs_pd_for_anomalies' in locals() and not logs_pd_for_anomalies.empty:
                    service_graph = create_service_graph(logs_pd_for_anomalies)
                else:
                    # If button wasn't clicked, run detect_anomalies just to get logs_pd
                    _, _, logs_pd_for_graph = detect_anomalies()
                    service_graph = create_service_graph(logs_pd_for_graph)
                st.pyplot(service_graph)

        if st.button("Export Security Anomalous Logs for Training", key="export_security_logs"):
            if not st.session_state.security_anomalous_logs_for_export.empty:
                export_index_name = "anomalous_security_logs_for_training"
                export_anomalous_logs_to_es(st.session_state.security_anomalous_logs_for_export, export_index_name)
            else:
                st.warning("No security anomalous logs detected to export. Please refresh data first.")

        st.info("Click 'Refresh Security Anomaly Data' to update the anomaly detection and optionally view the service interaction graph. Click 'Export...' to save the detected anomalous logs for model training.")


    # --- Performance Anomalies Sub-tab ---
    with anomaly_detection_subtabs[1]:
        st.subheader("Performance Anomalies (Latency)")
        # Initialize session state variables to store data for export
        if 'performance_anomalous_logs_for_export' not in st.session_state:
            st.session_state.performance_anomalous_logs_for_export = pd.DataFrame()

        if st.button("Detect Performance Anomalies", key="detect_performance_anomalies"):
            with st.spinner("Detecting performance anomalies based on latency..."):
                latency_summary_df, performance_anomalies_df, anomalous_performance_logs = detect_performance_anomalies()
                st.session_state.performance_anomalous_logs_for_export = anomalous_performance_logs # Store for export
                if not latency_summary_df.empty:
                    performance_anomaly_plot = plot_performance_anomalies(latency_summary_df, performance_anomalies_df)
                    st.pyplot(performance_anomaly_plot)
                    if not performance_anomalies_df.empty:
                        st.subheader("Detected Performance Anomalies:")
                        st.dataframe(performance_anomalies_df)
                    else:
                        st.info("No performance anomalies detected in the last 24 hours.")
                    st.success("Performance anomalies detected and displayed!")
                else:
                    st.info("No latency data available to detect performance anomalies.")

        if st.button("Export Performance Anomalous Logs for Training", key="export_performance_logs"):
            if not st.session_state.performance_anomalous_logs_for_export.empty:
                export_index_name = "anomalous_performance_logs_for_training"
                export_anomalous_logs_to_es(st.session_state.performance_anomalous_logs_for_export, export_index_name)
            else:
                st.warning("No performance anomalous logs detected to export. Please detect anomalies first.")

        st.info("Click 'Detect Performance Anomalies' to analyze request latency for unusual patterns. Click 'Export...' to save the detected anomalous logs for model training.")


# --- Request Monitoring Tab ---
with main_tabs[1]:
    st.header("Request Monitoring")
    request_tabs = st.tabs(["Request Success Rate", "Service Reliability"])

    # --- Request Success Rate Sub-tab ---
    with request_tabs[0]:
        st.header("Request Success Rate")
        if st.button("Calculate Latest Request Success Rate"):
            with st.spinner("Calculating Request Success Rate..."):
                _, _, logs_pd_for_sli = detect_anomalies()  # Re-run to get fresh logs_pd
                if logs_pd_for_sli is not None:
                    sli_value = calculate_sli(logs_pd_for_sli)
                    st.metric("Successful HTTP Request Rate", f"{sli_value:.2f}%")

                    logs_pd_for_sli["timestamp"] = pd.to_datetime(logs_pd_for_sli["@timestamp"])
                    logs_pd_for_sli["is_successful"] = logs_pd_for_sli["attributes.status_code"].astype(str).str.startswith('2')
                    sli_over_time = logs_pd_for_sli.groupby(logs_pd_for_sli["timestamp"].dt.floor("1H"))["is_successful"].mean() * 100

                    fig, ax = plt.subplots(figsize=(14, 6))
                    sli_over_time.plot(ax=ax, marker='o', color='blue', label="Request Success Rate (%)")
                    ax.axhline(y=99.95, color='green', linestyle='--', label="Target (99.95%)")
                    ax.set_xlabel("Time")
                    ax.set_ylabel("Request Success Rate (%)")
                    ax.set_title("Request Success Rate Over Time")
                    ax.legend()
                    st.pyplot(fig)

                    st.success("Request Success Rate calculated and displayed!")
                else:
                    st.warning("No log data available to calculate Request Success Rate.")
        else:
            st.info("Click 'Calculate Latest Request Success Rate' to see the current successful HTTP request rate.")

    # --- Service Reliability Sub-tab ---
    with request_tabs[1]:
        st.header("Service Reliability")
        if st.button("Check Latest Service Reliability"):
            with st.spinner("Checking Service Reliability..."):
                _, _, logs_pd_for_slo = detect_anomalies()  # Re-run to get fresh logs_pd
                if logs_pd_for_slo is not None:
                    slo_achieved, success_rate = calculate_slo(logs_pd_for_slo)
                    display_slo(slo_achieved, success_rate)
                    st.success("Service Reliability checked and displayed!")
                else:
                    st.warning("No log data available to check Service Reliability.")
        else:
            st.info("Click 'Check Latest Service Reliability' to see the current reliability status based on the last 2 days of logs.")

# --- System Health Checks Tab ---
with main_tabs[2]:
    st.header("System Health Checks")
    # Removed performance anomalies sub-tab from here as it's moved
    if st.button("Fetch System Metrics"):
        with st.spinner("Fetching system metrics..."):
            metrics_pd = fetch_metrics_data()
            if not metrics_pd.empty:
                st.write("Metrics Data Preview:")
                st.write(metrics_pd.head())
                st.write("Available Columns:")
                st.write(metrics_pd.columns)

                if 'metrics.employee_requests' in metrics_pd.columns:
                    metrics_pd['metrics.employee_requests'] = pd.to_numeric(
                        metrics_pd['metrics.employee_requests'], errors='coerce'
                    )
                    if metrics_pd['metrics.employee_requests'].notna().any():
                        fig_requests, ax_requests = plt.subplots(figsize=(14, 6))
                        metrics_pd["timestamp"] = pd.to_datetime(metrics_pd["@timestamp"])
                        metrics_pd.groupby(metrics_pd["timestamp"].dt.floor("1H"))['metrics.employee_requests'].mean().plot(
                            ax=ax_requests, marker='o', color='blue', label="Employee Requests"
                        )
                        ax_requests.set_xlabel("Time")
                        ax_requests.set_ylabel("Employee Requests")
                        ax_requests.set_title("Employee Requests Over Time")
                        ax_requests.legend()
                        st.pyplot(fig_requests)
                    else:
                        st.warning("No valid numeric data found in 'metrics.employee_requests'.")

                if 'metrics.http.server.active_requests' in metrics_pd.columns:
                    metrics_pd['metrics.http.server.active_requests'] = pd.to_numeric(
                        metrics_pd['metrics.http.server.active_requests'], errors='coerce'
                    )
                    if metrics_pd['metrics.http.server.active_requests'].notna().any():
                        fig_active_requests, ax_active_requests = plt.subplots(figsize=(14, 6))
                        metrics_pd["timestamp"] = pd.to_datetime(metrics_pd["@timestamp"])
                        metrics_pd.groupby(metrics_pd["timestamp"].dt.floor("1H"))['metrics.http.server.active_requests'].mean().plot(
                            ax=ax_active_requests, marker='o', color='green', label="Active HTTP Server Requests"
                        )
                        ax_active_requests.set_xlabel("Time")
                        ax_active_requests.set_ylabel("Active HTTP Server Requests")
                        ax_active_requests.set_title("Active HTTP Server Requests Over Time")
                        ax_active_requests.legend()
                        st.pyplot(fig_active_requests)
                    else:
                        st.warning("No valid numeric data found in 'metrics.http.server.active_requests'.")

                st.success("System metrics visualized successfully!")
            else:
                st.warning("No system metrics data available.")
    else:
        st.info("Click 'Fetch System Metrics' to retrieve system health data.")


# --- Defects Tab ---
with main_tabs[3]:
    st.header("Defects")
    if st.button("Fetch Latest Defects"):
        with st.spinner("Fetching defects from Elasticsearch..."):
            defects_pd = fetch_defects_data()
            if not defects_pd.empty:
                st.subheader("Recent Defects from Jira")
                st.dataframe(defects_pd)
                st.success("Defects fetched successfully!")
            else:
                st.info("No defects found in Elasticsearch index 'jira_defects'.")
    else:
        st.info("Click 'Fetch Latest Defects' to retrieve current defect information.")