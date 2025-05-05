import os
import json
import pytest
import sys
import yaml
from unittest.mock import patch, MagicMock

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules to test
from scripts.data_ingestion.consolidated_ingest_data import fetch_mitre_attack_data, fetch_otx_attack_data, fetch_vt_attack_data, save_data_to_json
from scripts.data_ingestion.normalize_data import normalize_mitre_data, normalize_otx_data, normalize_vt_data
from scripts.data_ingestion.store_data_in_db import create_tables, store_mitre_attack_data

# Test data
TEST_MITRE_DATA = {
    "objects": [
        {
            "id": "attack-pattern--00000000-0000-0000-0000-000000000001",
            "type": "attack-pattern",
            "name": "Test Technique",
            "description": "This is a test technique",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T0001"
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "initial-access"
                }
            ]
        }
    ]
}

TEST_OTX_DATA = [
    {
        "id": "otx-00000000-0000-0000-0000-000000000001",
        "indicator_type": "IPv4",
        "indicator": "192.168.1.1",
        "description": "This is a test indicator",
        "source": "AlienVault OTX",
        "timestamp": "2023-01-01T00:00:00Z"
    }
]

TEST_VT_DATA = [
    {
        "id": "vt-00000000-0000-0000-0000-000000000001",
        "type": "malware",
        "attributes": {
            "description": "This is a test malware",
            "severity": 5
        },
        "source": "VirusTotal",
        "timestamp": "2023-01-01T00:00:00Z"
    }
]

@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    return {
        "api_url": "https://test.example.com/api",
        "raw_data_path": "data/raw/test_data.json",
        "log_file_path": "logs/test.log",
        "otx_api_key": "test_otx_key",
        "vt_api_key": "test_vt_key",
        "database": {
            "dbname": "test_db",
            "user": "test_user",
            "password": "test_password",
            "host": "localhost",
            "port": "5432"
        }
    }

@pytest.fixture
def temp_dir(tmpdir):
    """Create temporary directories for testing."""
    data_dir = tmpdir.mkdir("data")
    raw_dir = data_dir.mkdir("raw")
    processed_dir = data_dir.mkdir("processed")
    return tmpdir

def test_fetch_mitre_attack_data():
    """Test fetching MITRE ATT&CK data."""
    with patch('scripts.data_ingestion.consolidated_ingest_data.Server') as mock_server:
        # Mock the TAXII server response
        mock_collection = MagicMock()
        mock_collection.get_objects.return_value = {'objects': TEST_MITRE_DATA['objects']}
        
        mock_api_root = MagicMock()
        mock_api_root.collections = [mock_collection]
        
        mock_server_instance = MagicMock()
        mock_server_instance.api_roots = [mock_api_root]
        
        mock_server.return_value = mock_server_instance
        
        # Call the function
        result = fetch_mitre_attack_data()
        
        # Verify the result
        assert result == TEST_MITRE_DATA
        assert len(result['objects']) == 1
        assert result['objects'][0]['type'] == 'attack-pattern'
        assert result['objects'][0]['name'] == 'Test Technique'

def test_fetch_otx_attack_data():
    """Test fetching AlienVault OTX data."""
    with patch('scripts.data_ingestion.consolidated_ingest_data.requests.get') as mock_get:
        # Mock the requests.get response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = TEST_OTX_DATA
        mock_get.return_value = mock_response
        
        # Call the function with a mock API key
        result = fetch_otx_attack_data()
        
        # Verify the result
        assert result == TEST_OTX_DATA
        assert len(result) == 1
        assert result[0]['indicator_type'] == 'IPv4'
        assert result[0]['indicator'] == '192.168.1.1'

def test_fetch_vt_attack_data():
    """Test fetching VirusTotal data."""
    with patch('scripts.data_ingestion.consolidated_ingest_data.requests.get') as mock_get:
        # Mock the requests.get response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': TEST_VT_DATA}
        mock_get.return_value = mock_response
        
        # Call the function with a mock API key
        result = fetch_vt_attack_data()
        
        # Verify the result
        assert result == TEST_VT_DATA
        assert len(result) == 1
        assert result[0]['type'] == 'malware'
        assert result[0]['attributes']['severity'] == 5

def test_save_data_to_json(temp_dir):
    """Test saving data to a JSON file."""
    # Define the file path
    file_path = os.path.join(temp_dir, "data", "raw", "test_data.json")
    
    # Call the function
    save_data_to_json(TEST_MITRE_DATA, file_path)
    
    # Verify the file was created and contains the correct data
    assert os.path.exists(file_path)
    with open(file_path, 'r') as f:
        saved_data = json.load(f)
    assert saved_data == TEST_MITRE_DATA

def test_normalize_mitre_data(temp_dir):
    """Test normalizing MITRE ATT&CK data."""
    # Define the file paths
    input_file_path = os.path.join(temp_dir, "data", "raw", "test_mitre_data.json")
    output_file_path = os.path.join(temp_dir, "data", "processed", "test_normalized_mitre_data.json")
    
    # Save test data to the input file
    with open(input_file_path, 'w') as f:
        json.dump(TEST_MITRE_DATA, f)
    
    # Call the function
    result = normalize_mitre_data(input_file_path, output_file_path)
    
    # Verify the output file was created and contains the correct data
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r') as f:
        normalized_data = json.load(f)
    
    # Verify the normalized data
    assert len(normalized_data) == 1
    assert normalized_data[0]['mitre_id'] == 'T0001'
    assert normalized_data[0]['name'] == 'Test Technique'
    assert normalized_data[0]['tactics'] == ['initial-access']

def test_normalize_otx_data(temp_dir):
    """Test normalizing AlienVault OTX data."""
    # Define the file paths
    input_file_path = os.path.join(temp_dir, "data", "raw", "test_otx_data.json")
    output_file_path = os.path.join(temp_dir, "data", "processed", "test_normalized_otx_data.json")
    
    # Save test data to the input file
    with open(input_file_path, 'w') as f:
        json.dump(TEST_OTX_DATA, f)
    
    # Call the function
    result = normalize_otx_data(input_file_path, output_file_path)
    
    # Verify the output file was created and contains the correct data
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r') as f:
        normalized_data = json.load(f)
    
    # Verify the normalized data
    assert len(normalized_data) == 1
    assert normalized_data[0]['indicator_type'] == 'IPv4'
    assert normalized_data[0]['indicator_value'] == '192.168.1.1'
    assert normalized_data[0]['source'] == 'AlienVault OTX'

def test_normalize_vt_data(temp_dir):
    """Test normalizing VirusTotal data."""
    # Define the file paths
    input_file_path = os.path.join(temp_dir, "data", "raw", "test_vt_data.json")
    output_file_path = os.path.join(temp_dir, "data", "processed", "test_normalized_vt_data.json")
    
    # Save test data to the input file
    with open(input_file_path, 'w') as f:
        json.dump(TEST_VT_DATA, f)
    
    # Call the function
    result = normalize_vt_data(input_file_path, output_file_path)
    
    # Verify the output file was created and contains the correct data
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r') as f:
        normalized_data = json.load(f)
    
    # Verify the normalized data
    assert len(normalized_data) == 1
    assert normalized_data[0]['threat_type'] == 'malware'
    assert normalized_data[0]['description'] == 'This is a test malware'
    assert normalized_data[0]['source'] == 'VirusTotal'

def test_create_tables():
    """Test creating database tables."""
    with patch('scripts.data_ingestion.store_data_in_db.Base.metadata.create_all') as mock_create_all:
        # Call the function
        create_tables()
        
        # Verify the function was called
        mock_create_all.assert_called_once()

def test_store_mitre_attack_data(temp_dir):
    """Test storing MITRE ATT&CK data in the database."""
    # Define the file path
    data_file_path = os.path.join(temp_dir, "data", "processed", "test_normalized_mitre_data.json")
    
    # Save test data to the file
    normalized_data = [
        {
            "id": "attack-pattern--00000000-0000-0000-0000-000000000001",
            "mitre_id": "T0001",
            "name": "Test Technique",
            "description": "This is a test technique",
            "tactics": ["initial-access"],
            "source": "MITRE ATT&CK",
            "timestamp": "2023-01-01T00:00:00Z"
        }
    ]
    with open(data_file_path, 'w') as f:
        json.dump(normalized_data, f)
    
    # Mock the SQLAlchemy session
    with patch('scripts.data_ingestion.store_data_in_db.Session') as mock_session:
        # Mock the session instance
        mock_session_instance = MagicMock()
        mock_session.return_value = mock_session_instance
        
        # Call the function
        store_mitre_attack_data(data_file_path)
        
        # Verify the session methods were called
        mock_session_instance.merge.assert_called()
        mock_session_instance.commit.assert_called_once()
        mock_session_instance.close.assert_called_once()
