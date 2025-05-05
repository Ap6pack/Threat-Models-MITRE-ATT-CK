import os
import json
import logging
import yaml
import pandas as pd
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
import pdfkit
from sqlalchemy import create_engine

# Load configuration
with open('config/settings.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Database configuration
db_config = config.get('database', {
    'dbname': 'threat_intelligence',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432'
})

# Set up logging
logging.basicConfig(filename='logs/app.log', level=logging.INFO)

def fetch_data_from_db():
    """
    Fetch threat data from the database.
    
    Returns:
        DataFrame containing threat data
    """
    try:
        # Create database connection
        db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['dbname']}"
        engine = create_engine(db_url)
        
        # Query mapped threat data
        query = """
        SELECT m.id, m.threat_id, m.technique_id, m.description, m.source, m.timestamp,
               t.technique_name
        FROM mapped_threat_data m
        LEFT JOIN mitre_attack_techniques t ON m.technique_id = t.mitre_attack_id
        """
        
        df = pd.read_sql_query(query, engine)
        logging.info(f"Fetched {len(df)} records from the database")
        return df
    
    except Exception as e:
        logging.error(f"Error fetching data from database: {str(e)}")
        return pd.DataFrame()

def fetch_data_from_file(file_path):
    """
    Fetch threat data from a JSON file.
    
    Args:
        file_path: Path to the JSON file
    
    Returns:
        DataFrame containing threat data
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        df = pd.DataFrame(data)
        logging.info(f"Fetched {len(df)} records from {file_path}")
        return df
    
    except Exception as e:
        logging.error(f"Error fetching data from file: {str(e)}")
        return pd.DataFrame()

def generate_html_report(data, template_file='reports/report_template.html', output_file='reports/threat_report.html'):
    """
    Generate an HTML report using a Jinja2 template.
    
    Args:
        data: DataFrame containing threat data
        template_file: Path to the Jinja2 template file
        output_file: Path to save the HTML report
    """
    try:
        # Ensure template directory exists
        template_dir = os.path.dirname(template_file)
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)
        
        # Check if template file exists, if not create a default one
        if not os.path.exists(template_file):
            create_default_template(template_file)
        
        # Set up Jinja2 environment
        env = Environment(loader=FileSystemLoader(os.path.dirname(template_file)))
        template = env.get_template(os.path.basename(template_file))
        
        # Convert DataFrame to list of dictionaries for Jinja2
        threat_data = data.to_dict('records')
        
        # Render template
        report_html = template.render(
            threat_data=threat_data,
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_threats=len(threat_data)
        )
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Write HTML report
        with open(output_file, 'w') as f:
            f.write(report_html)
        
        logging.info(f"HTML report generated and saved to {output_file}")
        return output_file
    
    except Exception as e:
        logging.error(f"Error generating HTML report: {str(e)}")
        return None

def create_default_template(template_file):
    """
    Create a default HTML report template.
    
    Args:
        template_file: Path to save the template
    """
    try:
        # Default template content
        template_content = """<!DOCTYPE html>
<html>
<head>
    <title>Threat Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { text-align: center; }
        .content { margin: 20px 0; }
        .threat-table { width: 100%; border-collapse: collapse; }
        .threat-table th, .threat-table td { border: 1px solid #ddd; padding: 8px; }
        .threat-table th { background-color: #f2f2f2; }
        .note { color: #666; font-style: italic; }
    </style>
</head>
<body>
    <h1>Cyber Threat Report</h1>
    <div class="content">
        <h2>Report Summary</h2>
        <p>Report generated on: {{ report_date }}</p>
        <p>Total threats analyzed: {{ total_threats }}</p>
    </div>
    <div class="content">
        <h2>Threat Visualizations</h2>
        <p class="note">Note: For interactive visualizations, please use the dashboard application.</p>
        <p>Static visualizations are available in the reports directory:</p>
        <ul>
            <li>Threat Types Distribution: threat_types_distribution.png</li>
            <li>Threats Over Time: threats_over_time.png</li>
        </ul>
    </div>
    <div class="content">
        <h2>Threat Data</h2>
        <table class="threat-table">
            <tr>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>Source</th>
                <th>Description</th>
                <th>Timestamp</th>
            </tr>
            {% for threat in threat_data %}
            <tr>
                <td>{{ threat.technique_id }}</td>
                <td>{{ threat.technique_name }}</td>
                <td>{{ threat.source }}</td>
                <td>{{ threat.description[:100] }}...</td>
                <td>{{ threat.timestamp }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>"""
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(template_file), exist_ok=True)
        
        # Write template file
        with open(template_file, 'w') as f:
            f.write(template_content)
        
        logging.info(f"Default template created at {template_file}")
    
    except Exception as e:
        logging.error(f"Error creating default template: {str(e)}")

def convert_html_to_pdf(html_file, pdf_file):
    """
    Convert HTML report to PDF using pdfkit.
    
    Args:
        html_file: Path to the HTML report
        pdf_file: Path to save the PDF report
    """
    try:
        # Check if pdfkit is available
        if 'pdfkit' not in globals():
            logging.warning("pdfkit module not available, skipping PDF generation")
            return None
        
        # Instead of converting the HTML file directly, create a minimal HTML string
        # with just the essential content and no external resources
        with open(html_file, 'r') as f:
            html_content = f.read()
        
        # Extract the threat data table from the HTML content
        import re
        table_match = re.search(r'<table class="threat-table">.*?</table>', html_content, re.DOTALL)
        table_html = table_match.group(0) if table_match else "<p>No threat data available</p>"
        
        # Create a completely self-contained HTML with no external resources
        minimal_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Threat Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        h1 {{ text-align: center; color: #333; }}
        p {{ margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Cyber Threat Report</h1>
    <p><strong>Report generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>Total threats analyzed:</strong> {len(html_content.split('<tr>')) - 2 if '<tr>' in html_content else 0}</p>
    <h2>Threat Data</h2>
    {table_html}
</body>
</html>"""
        
        # Write minimal HTML to a temporary file
        temp_html = 'reports/minimal_report.html'
        with open(temp_html, 'w') as f:
            f.write(minimal_html)
        
        # Convert the minimal HTML to PDF with minimal options
        pdfkit.from_file(temp_html, pdf_file, options={'quiet': ''})
        
        # Remove temporary file
        os.remove(temp_html)
        
        logging.info(f"PDF report generated and saved to {pdf_file}")
        return pdf_file
    
    except Exception as e:
        logging.error(f"Error converting HTML to PDF: {str(e)}")
        
        # Create an extremely simple PDF as a last resort
        try:
            ultra_simple_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Threat Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        h1 {{ text-align: center; }}
    </style>
</head>
<body>
    <h1>Cyber Threat Report</h1>
    <p>Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>This is a basic PDF report. For the full report, please refer to the HTML version.</p>
</body>
</html>"""
            
            # Write ultra simple HTML to a temporary file
            temp_html = 'reports/ultra_simple_report.html'
            with open(temp_html, 'w') as f:
                f.write(ultra_simple_html)
            
            # Try to convert with no options at all
            pdfkit.from_string(ultra_simple_html, pdf_file)
            
            # Remove temporary file
            os.remove(temp_html)
            
            logging.info(f"Ultra-simplified PDF report generated as fallback and saved to {pdf_file}")
            return pdf_file
        except Exception as fallback_error:
            logging.error(f"Error creating fallback PDF: {str(fallback_error)}")
            
            # As a last resort, create a text file with .pdf extension
            try:
                with open(pdf_file, 'w') as f:
                    f.write(f"Cyber Threat Report\n\nReport generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nThis is a text-only report. For the full report, please refer to the HTML version.")
                
                logging.info(f"Text-only report saved as {pdf_file}")
                return pdf_file
            except Exception as text_error:
                logging.error(f"Error creating text-only report: {str(text_error)}")
                return None

def generate_csv_report(data, output_file='reports/threat_report.csv'):
    """
    Generate a CSV report.
    
    Args:
        data: DataFrame containing threat data
        output_file: Path to save the CSV report
    """
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Write CSV report
        data.to_csv(output_file, index=False)
        
        logging.info(f"CSV report generated and saved to {output_file}")
        return output_file
    
    except Exception as e:
        logging.error(f"Error generating CSV report: {str(e)}")
        return None

def generate_json_report(data, output_file='reports/threat_report.json'):
    """
    Generate a JSON report.
    
    Args:
        data: DataFrame containing threat data
        output_file: Path to save the JSON report
    """
    try:
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Convert DataFrame to list of dictionaries
        threat_data = data.to_dict('records')
        
        # Write JSON report
        with open(output_file, 'w') as f:
            json.dump(threat_data, f, indent=4, default=str)
        
        logging.info(f"JSON report generated and saved to {output_file}")
        return output_file
    
    except Exception as e:
        logging.error(f"Error generating JSON report: {str(e)}")
        return None

def generate_all_reports():
    """
    Generate all report formats (HTML, PDF, CSV, JSON).
    """
    # Fetch data
    data = fetch_data_from_db()
    
    if data.empty:
        # Try to fetch from file if database is empty
        data = fetch_data_from_file('data/processed/mapped_threat_data.json')
    
    if data.empty:
        logging.error("No data available for reporting")
        return
    
    # Generate reports
    html_file = generate_html_report(data)
    
    if html_file:
        convert_html_to_pdf(html_file, html_file.replace('.html', '.pdf'))
    
    generate_csv_report(data)
    generate_json_report(data)
    
    logging.info("All reports generated successfully")

if __name__ == "__main__":
    generate_all_reports()
