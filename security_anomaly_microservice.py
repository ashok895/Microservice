# security_anomaly_service.py
from flask import Flask, jsonify, request
from flask_cors import CORS #  CORS
from elasticsearch import Elasticsearch
import eland as ed
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import numpy as np # Import numpy for np.nan

app = Flask(__name__)
# Enable CORS with specific configurations for preflight requests and custom headers
CORS(app,
     resources={r"/*": {"origins": "http://localhost:4200"}}, # Allow only your Angular app's origin
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], # Explicitly allow OPTIONS for preflight
     allow_headers=["Content-Type", "X-Elastic-Username", "X-Elastic-Password"]) # Explicitly allow custom headers

# --- Anomaly Detection Function (Adapted from original code) ---
def detect_security_anomalies(es_client_dynamic, time_range_hours: int = 24):
    """
    Detects security anomalies based on request counts and status codes.
    Returns pivot_df (for plotting), anomalous_logs (detailed anomalies), and raw logs.
    Accepts a dynamic Elasticsearch client.
    """
    stream_name_logs = "logs-generic.otel-default"
    df_logs = ed.DataFrame(es_client_dynamic, es_index_pattern=stream_name_logs)

    # Calculate time range dynamically
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=time_range_hours)

    query = {
        "range": {
            "@timestamp": {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat()
            }
        }
    }
    recent_logs = df_logs.es_query(query)
    logs_pd = ed.eland_to_pandas(recent_logs[[
        "@timestamp", "attributes.service_name",
        "attributes.status_code", "attributes.emp_id",
        "attributes.asctime", "attributes.latency"
    ]])

    # Data cleaning and feature engineering
    logs_pd["attributes.asctime"] = pd.to_datetime(logs_pd["attributes.asctime"], errors="coerce")
    logs_pd["timestamp"] = pd.to_datetime(logs_pd["@timestamp"])
    logs_pd["time_window"] = logs_pd["timestamp"].dt.floor("5min")

    request_counts = logs_pd.groupby([
        "time_window", "attributes.service_name", "attributes.status_code"
    ]).size().reset_index(name="count")

    pivot_df = request_counts.pivot_table(
        index=["time_window", "attributes.service_name"],
        columns=["attributes.status_code"],
        values="count",
        fill_value=0
    ).reset_index()

    # Ensure all possible status_code columns exist
    all_possible_status_codes = [200, 201, 204, 400, 401, 403, 404, 500, 502, 503]
    for code in all_possible_status_codes:
        if code not in pivot_df.columns:
            pivot_df[code] = 0

    features = [col for col in pivot_df.columns if col not in ["time_window", "attributes.service_name"]]
    X = pivot_df[features].values

    # Handle cases where X might be empty or contain non-finite values
    if X.size == 0 or not np.isfinite(X).all():
        print("Warning: Input data for IsolationForest is empty or contains non-finite values. Returning empty DataFrames.")
        # Ensure all returned DataFrames are truly empty and not just potentially problematic
        return pd.DataFrame(columns=pivot_df.columns), pd.DataFrame(columns=logs_pd.columns), pd.DataFrame(columns=logs_pd.columns)


    model = IsolationForest(contamination=0.05, random_state=0)
    pivot_df["anomaly"] = model.fit_predict(X)
    pivot_df["anomaly_score"] = model.decision_function(X)

    pivot_df["anomaly_score_inverted"] = -pivot_df["anomaly_score"]
    # Handle case where min is not defined for empty or single-value series
    if not pivot_df["anomaly_score_inverted"].empty:
        pivot_df["anomaly_score_normalized"] = pivot_df["anomaly_score_inverted"] - pivot_df["anomaly_score_inverted"].min()
    else:
        pivot_df["anomaly_score_normalized"] = 0 # Default if no data, or ensure it's handled as None later

    anomalies = pivot_df[pivot_df["anomaly"] == -1]
    anomalous_windows = anomalies[["time_window", "attributes.service_name", "anomaly_score_normalized"]]

    # Ensure consistency in column names for merging
    anomalous_logs = pd.merge(
        logs_pd,
        anomalous_windows.rename(columns={'anomaly_score_normalized': 'detected_anomaly_score_normalized'}), # Rename to avoid conflict
        on=["time_window", "attributes.service_name"],
        how="inner"
    )

    # Filter anomalous_logs to only include actual anomalies for export
    # This assumes 'anomaly_score_normalized' is a reliable indicator for actual anomalies
    anomalous_logs_filtered = anomalous_logs[anomalous_logs['detected_anomaly_score_normalized'].notna()]

    return pivot_df, anomalous_logs_filtered, logs_pd

def create_service_graph_data(logs_pd):
    """
    Creates data for a service interaction graph.
    Returns a dictionary with 'nodes' and 'edges'.
    """
    # Filter out rows where service_name is NaN before getting unique services
    # Replace NaN service names with a placeholder or drop them to ensure string IDs
    filtered_logs_pd = logs_pd.dropna(subset=["attributes.service_name"])

    if filtered_logs_pd.empty:
        return {"nodes": [], "edges": []}

    graph_nodes = []
    graph_edges = []

    # Ensure service names are treated as strings for node IDs
    services = filtered_logs_pd["attributes.service_name"].astype(str).unique()
    for service in services:
        graph_nodes.append({"id": service, "label": service, "type": "service"})

    service_interactions = filtered_logs_pd.groupby([
        "attributes.service_name", "attributes.status_code"
    ]).size().reset_index(name="count")

    for _, row in service_interactions.iterrows():
        source = str(row["attributes.service_name"]) # Ensure source is string
        status = str(row["attributes.status_code"]) # Ensure status is string for startsWith
        count = row["count"]

        # Define target nodes based on status
        if status.startswith(('4', '5')):
            target = f"Error ({status})"
            color = 'red'
            # Add error node if not already present
            if {"id": target, "label": target, "type": "status_error"} not in graph_nodes:
                graph_nodes.append({"id": target, "label": target, "type": "status_error"})
            graph_edges.append({
                "source": source,
                "target": target,
                "weight": count,
                "color": color,
                "type": "error"
            })
        elif status.startswith('2'):
            target = f"Success ({status})"
            color = 'green'
            # Add success node if not already present
            if {"id": target, "label": target, "type": "status_success"} not in graph_nodes:
                graph_nodes.append({"id": target, "label": target, "type": "status_success"})
            graph_edges.append({
                "source": source,
                "target": target,
                "weight": count,
                "color": color,
                "type": "success"
            })

    return {"nodes": graph_nodes, "edges": graph_edges}


@app.route('/security-anomalies', methods=['GET'])
def get_security_anomalies():
    try:
        # Get username and password from request headers
        es_username = request.headers.get('X-Elastic-Username')
        es_password = request.headers.get('X-Elastic-Password')

        if not es_username or not es_password:
            return jsonify({"error": "Elasticsearch username and password are required in X-Elastic-Username and X-Elastic-Password headers."}), 401

        # Initialize Elasticsearch client with dynamic credentials
        es_client_dynamic = Elasticsearch(
            "https://localhost:9200",
            basic_auth=(es_username, es_password),
            verify_certs=False,
            request_timeout=60,
            retry_on_timeout=True,
            max_retries=3,
            headers={'Accept': 'application/vnd.elasticsearch+json;compatible-with=8'}
        )

        # Get time_range_hours from query parameters, default to 24
        time_range_hours = int(request.args.get('time_range_hours', 24))

        pivot_df, anomalous_logs, raw_logs_pd = detect_security_anomalies(es_client_dynamic, time_range_hours)

        # Prepare data for JSON response
        # Convert Timestamps to ISO format strings for JSON serialization
        # Apply lambda function to handle each datetime object and potential NaT values

        # FIXED: Explicitly convert all np.nan in DataFrames to None (which jsonify converts to null)
        # This prevents 'NaN' string literals in JSON which cause parsing errors.
        pivot_df_cleaned = pivot_df.replace({np.nan: None})
        anomalous_logs_cleaned = anomalous_logs.replace({np.nan: None})

        pivot_df_json = []
        if not pivot_df_cleaned.empty:
            # Ensure time_window is string, handling potential NaT (Not a Time)
            pivot_df_cleaned['time_window'] = pivot_df_cleaned['time_window'].apply(lambda x: x.isoformat() if pd.notna(x) else None)
            pivot_df_json = pivot_df_cleaned[[
                "time_window", "attributes.service_name", "anomaly_score_normalized"
            ]].to_dict(orient="records")

        anomalous_logs_json = []
        if not anomalous_logs_cleaned.empty:
            # Ensure timestamp and time_window are strings, handling potential NaT
            anomalous_logs_cleaned['@timestamp'] = anomalous_logs_cleaned['@timestamp'].apply(lambda x: x.isoformat() if pd.notna(x) else None)
            anomalous_logs_cleaned['time_window'] = anomalous_logs_cleaned['time_window'].apply(lambda x: x.isoformat() if pd.notna(x) else None)
            anomalous_logs_json = anomalous_logs_cleaned[[
                "@timestamp", "attributes.service_name", "attributes.status_code", "detected_anomaly_score_normalized"
            ]].to_dict(orient="records")

        # Prepare service graph data - raw_logs_pd is passed to function which handles its own cleaning
        service_graph = create_service_graph_data(raw_logs_pd)

        return jsonify({
            "anomalous_logs": anomalous_logs_json,
            "anomaly_scores_over_time": pivot_df_json,
            "service_graph": service_graph
        })
    except Exception as e:
        # Log the full exception for debugging in a real scenario
        print(f"Error in get_security_anomalies: {e}")
        # Return a generic 500 error to the client, avoid exposing internal details
        return jsonify({"error": "An internal server error occurred while fetching security anomalies."}), 500

if __name__ == '__main__':
    # You might want to use a more robust WSGI server like Gunicorn in production
    app.run(host='0.0.0.0', port=5003, debug=True) # Ensure this port matches your curl command and Angular service
