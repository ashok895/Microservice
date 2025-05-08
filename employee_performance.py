#employee_performance.py
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
log_handler = logging.FileHandler("child_service_2.txt")
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
log_handler.setFormatter(formatter)
logging.basicConfig(level=logging.INFO, handlers=[log_handler])

def fetch_performance(tx, emp_id):
    query = """
    MATCH (e:Employee {emp_id: $emp_id})-[:HAS_PERFORMANCE]->(p:Performance)
    RETURN p.performance_id AS performance_id, p.year AS year, p.rating AS rating
    """
    result = tx.run(query, emp_id=emp_id)
    return [{"performance_id": record["performance_id"], "year": record["year"], "rating": record["rating"]} for record in result]

@app.before_request
def before_request():
    # Extract trace context from incoming request
    context = extract(request.headers)
    trace.set_span_in_context(context)

@app.route('/performance', methods=['GET'])
def get_performance():
    emp_id = request.args.get('emp_id')
    if not emp_id:
        return jsonify({"error": "Missing emp_id"}), 400

    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("fetch_performance_span"):
        with driver.session() as session:
            performance = session.read_transaction(fetch_performance, emp_id)
            return jsonify(performance), 200

@app.after_request
def log_response_info(response):
    log_data = {
        "ip": request.remote_addr,
        "service_name": "employee-performance-service",
        "status_code": response.status_code,
        "status_message": response.status,
        "request_payload": request.args.to_dict(),
        "response_payload": response.get_json()
    }
    logging.info(log_data)
    return response

if __name__ == '__main__':
    app.run(port=5002)