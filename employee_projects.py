#employee projects.py
from flask import Flask, jsonify, request
from neo4j import GraphDatabase
import logging
from pythonjsonlogger import jsonlogger
from opentelemetry import trace
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.propagate import extract

# Initialize Flask app
app = Flask(__name__)

# Configure Neo4j connection
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "ashok123"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

# Configure OpenTelemetry tracing
tracer_provider = TracerProvider()
trace.set_tracer_provider(tracer_provider)
otlp_trace_exporter = OTLPSpanExporter(endpoint="http://localhost:4000/v1/traces")
span_processor = BatchSpanProcessor(otlp_trace_exporter)
tracer_provider.add_span_processor(span_processor)
FlaskInstrumentor().instrument_app(app)

# Configure logging
log_handler = logging.FileHandler("child_service_1.txt")
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
log_handler.setFormatter(formatter)
logging.basicConfig(level=logging.INFO, handlers=[log_handler])

def fetch_projects(tx, emp_id):
    query = """
    MATCH (e:Employee {emp_id: $emp_id})-[:WORKS_ON]->(p:Project)
    RETURN p.project_id AS project_id, p.project_name AS project_name, p.role AS role
    """
    result = tx.run(query, emp_id=emp_id)
    return [{"project_id": record["project_id"], "project_name": record["project_name"], "role": record["role"]} for record in result]

@app.before_request
def before_request():
    # Extract trace context from incoming request
    context = extract(request.headers)
    trace.set_span_in_context(context)

@app.route('/projects', methods=['GET'])
def get_projects():
    emp_id = request.args.get('emp_id')
    if not emp_id:
        return jsonify({"error": "Missing emp_id"}), 400

    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("fetch_projects_span"):
        with driver.session() as session:
            projects = session.execute_read(fetch_projects, emp_id)  # Updated method
            return jsonify(projects), 200

@app.after_request
def log_response_info(response):
    log_data = {
        "ip": request.remote_addr,
        "service_name": "employee-projects-service",
        "status_code": response.status_code,
        "status_message": response.status,
        "request_payload": request.args.to_dict(),
        "response_payload": response.get_json()
    }
    logging.info(log_data)
    return response

if __name__ == '__main__':
    app.run(port=5001)