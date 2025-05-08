#app.py
import logging
from flask import Flask, request, jsonify
from pythonjsonlogger import jsonlogger
from neo4j import GraphDatabase
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from prometheus_flask_exporter import PrometheusMetrics
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.propagate import inject
import requests

# Initialize Flask app
app = Flask(__name__)

# Configure Neo4j connection
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ashok123"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# Create shared resource for all telemetry signals
resource = Resource.create({
    ResourceAttributes.SERVICE_NAME: "employee-service",
    ResourceAttributes.SERVICE_VERSION: "1.0.0"
})

# Configure OpenTelemetry tracing
tracer_provider = TracerProvider(resource=resource)
trace.set_tracer_provider(tracer_provider)

# Configure OpenTelemetry metrics
otlp_metrics_exporter = OTLPMetricExporter(
    endpoint="http://localhost:4000/v1/metrics",
    headers={"Content-Type": "application/x-protobuf"}
)
metrics_reader = PeriodicExportingMetricReader(
    exporter=otlp_metrics_exporter,
    export_interval_millis=10000
)
meter_provider = MeterProvider(resource=resource, metric_readers=[metrics_reader])
metrics.set_meter_provider(meter_provider)

# Configure OTLP trace exporter
otlp_trace_exporter = OTLPSpanExporter(
    endpoint="http://localhost:4000/v1/traces",
    headers={"Content-Type": "application/x-protobuf"}
)

# Set up the trace span processor
span_processor = BatchSpanProcessor(otlp_trace_exporter)
tracer_provider.add_span_processor(span_processor)

# Instrument Flask (automatically captures HTTP requests)
FlaskInstrumentor().instrument_app(app)

# Enable Prometheus metrics
metrics = PrometheusMetrics(app)

# Create custom metrics
request_counter = meter_provider.get_meter("employee_service").create_counter(
    name="employee_requests",
    description="Counts number of employee requests",
    unit="1"
)

# Configure logging to write JSON logs to app.txt
log_handler = logging.FileHandler("app.txt")
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
log_handler.setFormatter(formatter)

logging.basicConfig(
    level=logging.INFO,
    handlers=[
        log_handler,
        logging.StreamHandler()
    ]
)

def fetch_employee_details(tx, emp_id):
    query = """
    MATCH (e:Employee {emp_id: $emp_id})
    RETURN e.username AS username, e.password AS password, e.name AS name, e.department AS department
    """
    result = tx.run(query, emp_id=emp_id)
    return result.single()

@app.route('/employee/details', methods=['GET'])
def get_employee_details():
    """Fetch employee details along with projects and performance based on emp_id, username, and password."""
    emp_id = request.args.get('emp_id')
    username = request.args.get('username')
    password = request.args.get('password')

    # Check for missing parameters
    if not emp_id or not username or not password:
        logging.warning("Missing required parameters")
        return jsonify({"error": "Missing required parameters"}), 400

    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("parent_service_span") as parent_span:
        try:
            # Validate employee credentials using Neo4j
            with driver.session() as session:
                employee = session.read_transaction(fetch_employee_details, emp_id)
                if not employee:
                    logging.warning(f"Employee ID {emp_id} not found")
                    return jsonify({"error": "Employee ID not found"}), 404

                if employee["username"] != username or employee["password"] != password:
                    logging.warning(f"Invalid credentials for Employee ID {emp_id}")
                    return jsonify({"error": "Unauthorized"}), 401

            # Inject trace context into headers
            headers = {}
            inject(headers)

            # Call child services with trace context
            projects_response = requests.get(f"http://localhost:5001/projects?emp_id={emp_id}", headers=headers)
            performance_response = requests.get(f"http://localhost:5002/performance?emp_id={emp_id}", headers=headers)

            # Check for errors in child service responses
            if projects_response.status_code != 200:
                logging.error(f"Error fetching projects: {projects_response.text}")
                return jsonify({"error": "Error fetching projects"}), 500

            if performance_response.status_code != 200:
                logging.error(f"Error fetching performance: {performance_response.text}")
                return jsonify({"error": "Error fetching performance"}), 500

            parent_span.add_event("Called child services successfully")

            # Increment custom metric
            request_counter.add(1, {"endpoint": "/employee/details"})

            # Return combined response
            return jsonify({
                "employee": {"emp_id": emp_id, "name": employee["name"], "department": employee["department"]},
                "projects": projects_response.json(),
                "performance": performance_response.json()
            }), 200

        except Exception as e:
            logging.error(f"Error in /employee/details: {e}")
            return jsonify({"error": "Internal server error"}), 500

@app.after_request
def log_response_info(response):
    """Log request and response details after each request."""
    log_data = {
        "ip": request.remote_addr,
        "service_name": "employee-service",
        "status_code": response.status_code,
        "status_message": response.status,
        "request_payload": request.args.to_dict(),
        "response_payload": response.get_json()
    }
    logging.info(log_data)
    return response

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    logging.error("Resource not found")
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logging.error("Internal server error")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)