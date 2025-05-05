import os
import logging
import yaml
import argparse
from datetime import datetime

# Import modules from each component
from data_ingestion.consolidated_ingest_data import fetch_and_save_all_data
from data_ingestion.normalize_data import normalize_all_data
from data_ingestion.store_data_in_db import store_all_data
from mapping.consolidated_mapping_algorithm import map_threat_data_workflow
from visualization.consolidated_dashboard import generate_static_visualizations, run_interactive_dashboard
from reporting.generate_reports import generate_all_reports

# Set up logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    filename='logs/app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def load_config():
    """
    Load configuration from YAML file.
    
    Returns:
        Dictionary containing configuration settings
    """
    try:
        with open('config/settings.yaml', 'r') as f:
            config = yaml.safe_load(f)
        logging.info("Configuration loaded successfully")
        return config
    except Exception as e:
        logging.error(f"Error loading configuration: {str(e)}")
        return {}

def run_data_ingestion():
    """
    Run the data ingestion process.
    """
    logging.info("Starting data ingestion process")
    try:
        # Fetch data from all sources
        fetch_and_save_all_data()
        
        # Normalize the data
        normalize_all_data()
        
        # Store the data in the database
        store_all_data()
        
        logging.info("Data ingestion process completed successfully")
        return True
    except Exception as e:
        logging.error(f"Error in data ingestion process: {str(e)}")
        return False

def run_mapping():
    """
    Run the mapping process.
    """
    logging.info("Starting mapping process")
    try:
        # Map threat data to MITRE ATT&CK techniques
        map_threat_data_workflow()
        
        logging.info("Mapping process completed successfully")
        return True
    except Exception as e:
        logging.error(f"Error in mapping process: {str(e)}")
        return False

def run_visualization(interactive=False):
    """
    Run the visualization process.
    
    Args:
        interactive: Whether to run the interactive dashboard
    """
    logging.info("Starting visualization process")
    try:
        # Generate static visualizations
        generate_static_visualizations()
        
        # Run interactive dashboard if requested
        if interactive:
            run_interactive_dashboard()
        
        logging.info("Visualization process completed successfully")
        return True
    except Exception as e:
        logging.error(f"Error in visualization process: {str(e)}")
        return False

def run_reporting():
    """
    Run the reporting process.
    """
    logging.info("Starting reporting process")
    try:
        # Generate all reports
        generate_all_reports()
        
        logging.info("Reporting process completed successfully")
        return True
    except Exception as e:
        logging.error(f"Error in reporting process: {str(e)}")
        return False

def run_full_workflow(interactive=False):
    """
    Run the full workflow from data ingestion to reporting.
    
    Args:
        interactive: Whether to run the interactive dashboard
    """
    logging.info("Starting full workflow")
    
    # Load configuration
    config = load_config()
    
    # Run each step of the workflow
    if run_data_ingestion():
        if run_mapping():
            if run_visualization(interactive):
                if run_reporting():
                    logging.info("Full workflow completed successfully")
                    return True
    
    logging.error("Full workflow failed")
    return False

def setup_argparse():
    """
    Set up command-line argument parsing.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Threat Models and MITRE ATT&CK Mapping Tool')
    
    parser.add_argument('--ingest', action='store_true', help='Run data ingestion process')
    parser.add_argument('--map', action='store_true', help='Run mapping process')
    parser.add_argument('--visualize', action='store_true', help='Run visualization process')
    parser.add_argument('--report', action='store_true', help='Run reporting process')
    parser.add_argument('--interactive', action='store_true', help='Run interactive dashboard')
    parser.add_argument('--all', action='store_true', help='Run full workflow')
    
    return parser.parse_args()

if __name__ == "__main__":
    # Parse command-line arguments
    args = setup_argparse()
    
    # Run the requested processes
    if args.all:
        run_full_workflow(args.interactive)
    else:
        if args.ingest:
            run_data_ingestion()
        
        if args.map:
            run_mapping()
        
        if args.visualize:
            run_visualization(args.interactive)
        
        if args.report:
            run_reporting()
        
        # If no specific process is requested, run the full workflow
        if not (args.ingest or args.map or args.visualize or args.report):
            run_full_workflow(args.interactive)
