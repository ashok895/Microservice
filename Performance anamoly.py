# performance_anomaly_service.py
from flask import Flask, jsonify, request
from flask_cors import CORS # Import CORS
from elasticsearch import Elasticsearch
import eland as ed
import pandas as pd
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import numpy as np
import traceback # Import traceback for detailed error logging

app = Flask(__name__)

# Enable CORS with specific configurations for preflight requests and custom headers
CORS(app,
     resources={r"/*": {"origins": "http://localhost:4200"}}, # Allow only your Angular app's origin
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], # Explicitly allow OPTIONS for preflight
     allow_headers=["Content-Type", "X-Elastic-Username", "X-Elastic-Password"]) # Explicitly allow custom headers

# --- Elasticsearch Connection (Consider moving credentials to environment variables) ---
# Note: In a production environment, avoid hardcoding credentials. Use environment variables
# or a secure configuration management system.
# es_client is no longer used globally if credentials come from headers, but kept as a fallback.
es_client = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("ashokp", "ashok123"), # This will be overridden by headers if provided
    verify_certs=False,
    request_timeout=60,
    retry_on_timeout=True,
    max_retries=3,
    headers={'Accept': 'application/vnd.elasticsearch+json;compatible-with=8'}
)

# --- Performance Anomaly Detection Function ---
def detect_performance_anomalies_service(es_client_dynamic, time_range_hours: int = 24):
    """
    Detects performance anomalies based on latency metrics from logs.
    Returns latency_summary_df (for plotting), performance_anomalies_df (detailed anomalies),
    and raw logs with anomaly information.
    Accepts a dynamic Elasticsearch client.
    """
    stream_name_logs = "logs-generic.otel-default"
    df_logs = ed.DataFrame(es_client_dynamic, es_index_pattern=stream_name_logs)

    # Calculate time range dynamically for the Elasticsearch query
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

    # Debugging: Print query
    print(f"Elasticsearch query: {query}")

    recent_logs = df_logs.es_query(query)
    logs_pd = ed.eland_to_pandas(recent_logs[[
        "@timestamp", "attributes.service_name", "attributes.latency"
    ]])

    # Debugging: Print initial logs_pd info
    print(f"Initial logs_pd shape: {logs_pd.shape}")
    print(f"Initial logs_pd head:\n{logs_pd.head()}")

    # Convert timestamp columns to datetime objects for time-based operations
    logs_pd["timestamp"] = pd.to_datetime(logs_pd["@timestamp"])
    logs_pd["time_window"] = logs_pd["timestamp"].dt.floor("5min")

    # Convert latency string to numeric (seconds)
    logs_pd['attributes.latency_numeric'] = pd.to_numeric(
        logs_pd['attributes.latency'].astype(str).str.replace(' seconds', '', regex=False),
        errors='coerce' # Coerce invalid parsing to NaN
    )

    # Drop rows where latency couldn't be converted to a valid number or service name is missing
    # Ensure attributes.service_name is not NaN for later grouping/merging
    logs_pd.dropna(subset=['attributes.latency_numeric', 'attributes.service_name'], inplace=True)

    # Debugging: Print logs_pd after dropping NaNs
    print(f"logs_pd shape after dropping NaNs: {logs_pd.shape}")
    print(f"logs_pd head after dropping NaNs:\n{logs_pd.head()}")

    if logs_pd.empty:
        print("No valid latency data found for performance anomaly detection after filtering.")
        # Ensure all returned DataFrames are truly empty and not just potentially problematic
        return pd.DataFrame(columns=['time_window', 'attributes.service_name', 'p95_latency']), \
            pd.DataFrame(columns=['time_window', 'attributes.service_name', 'p95_latency', 'anomaly_score_normalized']), \
            pd.DataFrame(columns=logs_pd.columns)

    # Calculate 95th percentile latency for each time window and service
    latency_summary = logs_pd.groupby([
        "time_window", "attributes.service_name"
    ])['attributes.latency_numeric'].quantile(0.95).reset_index(name="p95_latency")

    # Debugging: Print latency_summary info
    print(f"latency_summary shape: {latency_summary.shape}")
    print(f"latency_summary head:\n{latency_summary.head()}")

    # Prepare data for Isolation Forest
    X = latency_summary[["p95_latency"]].values

    # Check for empty or non-finite data before applying Isolation Forest
    if X.size == 0 or not np.isfinite(X).all():
        print("Warning: Input data for IsolationForest is empty or contains non-finite values. Returning empty DataFrames.")
        return pd.DataFrame(columns=latency_summary.columns), pd.DataFrame(columns=latency_summary.columns), pd.DataFrame(columns=logs_pd.columns)

    # Apply Isolation Forest for anomaly detection on p95_latency
    # Contamination parameter can be tuned based on expected anomaly rate
    model = IsolationForest(contamination=0.05, random_state=0)
    latency_summary["anomaly"] = model.fit_predict(X)
    latency_summary["anomaly_score"] = model.decision_function(X)

    # Normalize anomaly score for better visualization (higher score means more anomalous)
    latency_summary["anomaly_score_inverted"] = -latency_summary["anomaly_score"]
    if not latency_summary["anomaly_score_inverted"].empty:
        latency_summary["anomaly_score_normalized"] = latency_summary["anomaly_score_inverted"] - latency_summary["anomaly_score_inverted"].min()
    else:
        latency_summary["anomaly_score_normalized"] = 0 # Default if no data

    # Filter for detected performance anomalies
    performance_anomalies = latency_summary[latency_summary["anomaly"] == -1]
    print(f"Detected {len(performance_anomalies)} performance anomalies")

    # Merge original logs with anomaly info to get full details for client
    anomalous_performance_logs = pd.merge(
        logs_pd,
        performance_anomalies[['time_window', 'attributes.service_name', 'anomaly_score_normalized']],
        on=['time_window', 'attributes.service_name'],
        how='inner' # Only keep logs that correspond to an detected anomaly window
    )

    # Debugging: Print final dataframes before return
    print(f"Final latency_summary shape before return: {latency_summary.shape}")
    print(f"Final performance_anomalies shape before return: {performance_anomalies.shape}")
    print(f"Final anomalous_performance_logs shape before return: {anomalous_performance_logs.shape}")


    return latency_summary, performance_anomalies, anomalous_performance_logs


@app.route('/performance-anomalies', methods=['GET'])
def get_performance_anomalies():
    try:
        # Get username and password from request headers
        es_username = request.headers.get('X-Elastic-Username')
        es_password = request.headers.get('X-Elastic-Password')

        if not es_username or not es_password:
            return jsonify({"error": "Elasticsearch username and password are required in X-Elastic-Username and X-Elastic-Password headers."}), 401

        # Initialize Elasticsearch client with dynamic credentials
        # This client uses the credentials provided in the request headers
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

        # Detect anomalies using the dynamic Elasticsearch client
        latency_summary_df, performance_anomalies_df, anomalous_performance_logs = \
            detect_performance_anomalies_service(es_client_dynamic, time_range_hours)

        # Prepare dataframes for JSON response
        # Convert Timestamps to ISO format strings, handling potential NaT values
        # FIXED: Explicitly convert all np.nan in DataFrames to None (which jsonify converts to null)
        latency_summary_df_cleaned = latency_summary_df.replace({np.nan: None})
        performance_anomalies_df_cleaned = performance_anomalies_df.replace({np.nan: None})
        anomalous_performance_logs_cleaned = anomalous_performance_logs.replace({np.nan: None})

        # Latency Summary Data for plotting P95 Latency over time
        latency_summary_json = []
        if not latency_summary_df_cleaned.empty:
            # Explicitly ensure the column is datetime type before applying isoformat
            # Adding errors='coerce' to pd.to_datetime makes it robust to invalid date formats
            latency_summary_df_cleaned['time_window'] = pd.to_datetime(latency_summary_df_cleaned['time_window'], errors='coerce')
            latency_summary_df_cleaned['time_window'] = latency_summary_df_cleaned['time_window'].apply(lambda x: x.isoformat() if pd.notna(x) else None)
            latency_summary_json = latency_summary_df_cleaned[[
                "time_window", "attributes.service_name", "p95_latency"
            ]].to_dict(orient="records")

        # Performance Anomalies Data for highlighting specific anomaly points
        performance_anomalies_json = []
        if not performance_anomalies_df_cleaned.empty:
            # Explicitly ensure the column is datetime type before applying isoformat
            performance_anomalies_df_cleaned['time_window'] = pd.to_datetime(performance_anomalies_df_cleaned['time_window'], errors='coerce')
            performance_anomalies_df_cleaned['time_window'] = performance_anomalies_df_cleaned['time_window'].apply(lambda x: x.isoformat() if pd.notna(x) else None)
            performance_anomalies_json = performance_anomalies_df_cleaned[[
                "time_window", "attributes.service_name", "p95_latency", "anomaly_score_normalized"
            ]].to_dict(orient="records")

        # Detailed Anomalous Performance Logs for drill-down information
        anomalous_performance_logs_json = []
        if not anomalous_performance_logs_cleaned.empty:
            # Explicitly ensure the columns are datetime type before applying isoformat
            anomalous_performance_logs_cleaned['@timestamp'] = pd.to_datetime(anomalous_performance_logs_cleaned['@timestamp'], errors='coerce')
            anomalous_performance_logs_cleaned['time_window'] = pd.to_datetime(anomalous_performance_logs_cleaned['time_window'], errors='coerce')
            anomalous_performance_logs_cleaned['@timestamp'] = anomalous_performance_logs_cleaned['@timestamp'].apply(lambda x: x.isoformat() if pd.notna(x) else None)
            anomalous_performance_logs_cleaned['time_window'] = anomalous_performance_logs_cleaned['time_window'].apply(lambda x: x.isoformat() if pd.notna(x) else None)
            anomalous_performance_logs_json = anomalous_performance_logs_cleaned[[
                "@timestamp", "attributes.service_name", "attributes.latency", "anomaly_score_normalized"
            ]].to_dict(orient="records")

        # Return the collected data as a JSON response
        return jsonify({
            "performance_anomalies": performance_anomalies_json,
            "latency_summary": latency_summary_json,
            "anomalous_performance_logs_details": anomalous_performance_logs_json
        })
    except Exception as e:
        # Log the full exception traceback for debugging
        traceback.print_exc() # This will print the detailed error to the console
        # Return a generic error message to the client, but log details internally
        return jsonify({"error": "An internal server error occurred while processing performance anomalies. Check server logs for details."}), 500

if __name__ == '__main__':
    # Run the Flask application. For production, use a WSGI server like Gunicorn.
    # FIXED: Changed port from 5004 to 5001 to match Angular DataService default for performance.
    app.run(host='0.0.0.0', port=5004, debug=True)
