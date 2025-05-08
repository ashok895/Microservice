import sqlite3
import csv

DB_FILE = 'Employee.db'

def export_to_csv(query, output_file):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    headers = [description[0] for description in cursor.description]
    conn.close()

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

# Export employees, projects, and performance data
export_to_csv("SELECT * FROM employees", "employees.csv")
export_to_csv("SELECT * FROM employee_projects", "projects.csv")
export_to_csv("SELECT * FROM employee_performance", "performance.csv")