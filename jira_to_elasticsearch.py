import logging
from jira import JIRA
from elasticsearch import Elasticsearch
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# Configure Jira connection
JIRA_URL = "https://ashokperumal461.atlassian.net"
JIRA_USERNAME = "ashokperumal461@gmail.com"
JIRA_API_TOKEN = "ATATT3xFfGF04AHq-0zUp45GVBWL5vr8GT72ERuqgeJlHwL0PJFgGJT41nlhcyRhwV411ESGioA-gfDGphg6WyJrPrYjZ7SIYkDgLo0OQxCYsKOrgUqNFiZutqYZIP2JLJIcrPX-CqPf2OfUfdCFx4xx4iB5wRpjqDDq5JsAbGctUSXaPBvE5Tk=869DD951"

# Connect to Jira
try:
    jira = JIRA(
        server=JIRA_URL,
        basic_auth=(JIRA_USERNAME, JIRA_API_TOKEN),
        options={'verify': False}  # Disable SSL verification
    )
    logging.info("Connected to Jira successfully.")
except Exception as e:
    logging.error(f"Failed to connect to Jira: {e}")
    raise

# Connect to Elasticsearch
try:
    es = Elasticsearch(
        "https://localhost:9200",
        basic_auth=("ashokp", "ashok123"),
        verify_certs=False,
        request_timeout=60,
        retry_on_timeout=True,
        max_retries=3,
        headers={'Accept': 'application/vnd.elasticsearch+json;compatible-with=8'}
    )
    logging.info("Connected to Elasticsearch successfully.")
except Exception as e:
    logging.error(f"Failed to connect to Elasticsearch: {e}")
    raise

def fetch_jira_issue_by_key(issue_key):
    """Fetch a Jira issue by its key and ensure it is of type 'Bug'."""
    try:
        logging.info(f"Fetching issue with key: {issue_key}")
        issue = jira.issue(issue_key)

        # Check if the issue type is 'Bug'
        if issue.fields.issuetype.name.lower() == "bug":
            defect = {
                "key": issue.key,
                "summary": issue.fields.summary,
                "description": issue.fields.description,
                "issue_type": issue.fields.issuetype.name,
                "priority": issue.fields.priority.name if hasattr(issue.fields, 'priority') and issue.fields.priority else "Medium",
                "status": issue.fields.status.name,
                "created": issue.fields.created,
                "updated": issue.fields.updated
            }
            logging.info(f"Fetched issue: {defect['key']} - {defect['summary']}")
            return defect
        else:
            logging.warning(f"Issue {issue_key} is not of type 'Bug', it's {issue.fields.issuetype.name}.")
            return None
    except Exception as e:
        logging.error(f"Failed to fetch issue with key {issue_key}: {e}")
        if hasattr(e, 'response') and e.response:
            logging.error(f"Response status: {e.response.status_code}")
            logging.error(f"Response text: {e.response.text}")
        return None

def fetch_bugs_with_label(label):
    """Fetch all bugs with a specific label."""
    try:
        jql_query = f'issuetype = Bug AND labels = "{label}"'
        logging.info(f"Searching for bugs with query: {jql_query}")

        # Execute the JQL query
        issues = jira.search_issues(jql_query, maxResults=100)

        logging.info(f"Found {len(issues)} bugs with label '{label}'")

        defects = []
        for issue in issues:
            defect = {
                "key": issue.key,
                "summary": issue.fields.summary,
                "description": issue.fields.description,
                "issue_type": issue.fields.issuetype.name,
                "priority": issue.fields.priority.name if hasattr(issue.fields, 'priority') and issue.fields.priority else "Medium",
                "status": issue.fields.status.name,
                "created": issue.fields.created,
                "updated": issue.fields.updated,
                "labels": issue.fields.labels if hasattr(issue.fields, 'labels') else []  # Labels are already strings
            }
            defects.append(defect)
            logging.info(f"Processed bug: {defect['key']} - {defect['summary']}")

        return defects
    except Exception as e:
        logging.error(f"Failed to fetch bugs with label '{label}': {e}")
        if hasattr(e, 'response') and e.response:
            logging.error(f"Response status: {e.response.status_code}")
            logging.error(f"Response text: {e.response.text}")
        return []

def export_defect_to_file(defect, file_name):
    """Export a defect to a file."""
    try:
        with open(file_name, 'w', encoding='utf-8') as file:
            file.write(f"Key: {defect['key']}\n")
            file.write(f"Summary: {defect['summary']}\n")
            file.write(f"Description: {defect['description']}\n")
            file.write(f"Issue Type: {defect['issue_type']}\n")
            file.write(f"Priority: {defect['priority']}\n")
            file.write(f"Status: {defect['status']}\n")
            file.write(f"Created: {defect['created']}\n")
            file.write(f"Updated: {defect['updated']}\n")
            if 'labels' in defect:
                file.write(f"Labels: {', '.join(defect['labels'])}\n")
        logging.info(f"Exported defect to {file_name}.")
    except Exception as e:
        logging.error(f"Failed to export defect to file: {e}")

def export_defect_to_elasticsearch(defect, index_name):
    """Export a defect to Elasticsearch with additional metadata."""
    try:
        # Enrich defect data with additional fields
        enriched_defect = defect.copy()
        enriched_defect["timestamp"] = datetime.now().isoformat()
        enriched_defect["source"] = "jira"
        enriched_defect["defect_severity"] = defect.get("priority", "Medium").lower()

        # Use the defect key as the document ID to avoid duplicates
        es.index(index=index_name, id=defect["key"], document=enriched_defect)
        logging.info(f"Exported defect to Elasticsearch index '{index_name}' with ID '{defect['key']}'.")
    except Exception as e:
        logging.error(f"Failed to export defect to Elasticsearch: {e}")

def export_defects_to_elasticsearch(defects, index_name):
    """Export multiple defects to Elasticsearch."""
    if not defects:
        logging.warning("No defects to export to Elasticsearch.")
        return

    for defect in defects:
        export_defect_to_elasticsearch(defect, index_name)

    logging.info(f"Exported {len(defects)} defects to Elasticsearch index '{index_name}'.")

if __name__ == "__main__":
    # Label to search for
    label = "Predict"

    # Fetch all bugs with the specified label
    defects = fetch_bugs_with_label(label)

    if defects:
        # Export to Elasticsearch
        export_defects_to_elasticsearch(defects, "jira_defects")

        # Export the first defect to a file as an example (optional)
        if len(defects) > 0:
            export_defect_to_file(defects[0], "sample_defect_export.txt")

        logging.info(f"Successfully processed {len(defects)} bugs with label '{label}'")
    else:
        logging.warning(f"No bugs found with label '{label}'")