import os
import sys
import yaml
import logging

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from integrations.soar.soar_integration import (
    TheHiveIntegration,
    DemistoIntegration,
    SwimlaneIntegration,
    SOARManager,
    ThreatResponseWorkflow
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_test_config():
    with open('config/test_soar_config.yaml', 'r') as f:
        return yaml.safe_load(f)


def test_soar_availability():
    """Test if SOAR platforms are available."""
    config = load_test_config()
    
    # Test TheHive
    thehive = TheHiveIntegration(config['soar']['thehive'])
    print(f"TheHive available: {thehive.is_available()}")
    
    # Test Demisto
    demisto = DemistoIntegration(config['soar']['demisto'])
    print(f"Demisto available: {demisto.is_available()}")
    
    # Test Swimlane
    swimlane = SwimlaneIntegration(config['soar']['swimlane'])
    print(f"Swimlane available: {swimlane.is_available()}")


def test_create_case():
    """Test creating a case in each SOAR platform."""
    config = load_test_config()
    soar_manager = SOARManager(config)
    
    # Create a test case
    case_ids = soar_manager.create_case_in_all(
        title="Test Case from MITRE ATT&CK Mapping Tool",
        description="This is a test case created by the MITRE ATT&CK Mapping Tool",
        severity="medium",
        tags=["test", "mitre", "attack"],
        artifacts=[
            {
                "type": "technique",
                "value": "T1566",
                "description": "Phishing: Spearphishing Attachment",
                "tags": ["mitre", "technique"]
            }
        ]
    )
    
    print(f"Created cases: {case_ids}")
    return case_ids


def test_create_task(case_ids):
    """Test creating tasks in each SOAR platform."""
    config = load_test_config()
    soar_manager = SOARManager(config)
    
    # Create a test task
    task_ids = soar_manager.create_task_in_all(
        case_ids,
        title="Test Task",
        description="This is a test task created by the MITRE ATT&CK Mapping Tool",
        status="New"
    )
    
    print(f"Created tasks: {task_ids}")
    return task_ids


def test_execute_playbook(case_ids):
    """Test executing playbooks in each SOAR platform."""
    config = load_test_config()
    soar_manager = SOARManager(config)
    
    # Execute a test playbook
    execution_ids = soar_manager.execute_playbook_in_all(
        case_ids,
        playbook_id="mitre_investigation"
    )
    
    print(f"Executed playbooks: {execution_ids}")
    return execution_ids


def test_workflow():
    """Test the entire threat response workflow."""
    config = load_test_config()
    workflow = ThreatResponseWorkflow(config)
    
    # Create test threat data
    threat_data = [
        {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "description": "Phishing: Spearphishing Attachment"
        },
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "description": "Command and Scripting Interpreter: PowerShell"
        }
    ]
    
    # Run the workflow
    results = workflow.run(threat_data)
    print(f"Workflow results: {results}")
    return results


if __name__ == "__main__":
    print("Testing SOAR integration...")
    test_soar_availability()
    
    case_ids = test_create_case()
    if case_ids:
        test_create_task(case_ids)
        test_execute_playbook(case_ids)
    
    test_workflow()
    print("Testing complete!")