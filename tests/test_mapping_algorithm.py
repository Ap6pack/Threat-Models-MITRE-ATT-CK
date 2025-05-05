import os
import json
import pytest
import sys
import pickle
from unittest.mock import patch, MagicMock

# Add the parent directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules to test
from scripts.mapping.consolidated_mapping_algorithm import (
    train_model, save_model, load_model, predict_technique, 
    map_mitre_to_stix, map_threat_data, save_mappings_to_file
)

# Test data
TEST_THREAT_OBJECTS = [
    {
        "id": "attack-pattern--00000000-0000-0000-0000-000000000001",
        "type": "attack-pattern",
        "name": "Test Technique 1",
        "description": "This is a test technique for phishing attacks",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T0001"
            }
        ]
    },
    {
        "id": "attack-pattern--00000000-0000-0000-0000-000000000002",
        "type": "attack-pattern",
        "name": "Test Technique 2",
        "description": "This is a test technique for malware execution",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T0002"
            }
        ]
    }
]

TEST_MITRE_DATA = {
    "objects": TEST_THREAT_OBJECTS
}

@pytest.fixture
def temp_dir(tmpdir):
    """Create temporary directories for testing."""
    models_dir = tmpdir.mkdir("models")
    data_dir = tmpdir.mkdir("data")
    processed_dir = data_dir.mkdir("processed")
    return tmpdir

def test_train_model():
    """Test training a machine learning model."""
    # Call the function
    model, vectorizer = train_model(TEST_THREAT_OBJECTS, model_type='naive_bayes')
    
    # Verify the model and vectorizer were created
    assert model is not None
    assert vectorizer is not None
    
    # Test with logistic regression
    model, vectorizer = train_model(TEST_THREAT_OBJECTS, model_type='logistic_regression')
    assert model is not None
    assert vectorizer is not None

def test_save_and_load_model(temp_dir):
    """Test saving and loading a machine learning model."""
    # Train a model
    model, vectorizer = train_model(TEST_THREAT_OBJECTS)
    
    # Define file paths
    model_path = os.path.join(temp_dir, "models", "test_model.pkl")
    vectorizer_path = os.path.join(temp_dir, "models", "test_vectorizer.pkl")
    
    # Save the model
    save_model(model, vectorizer, model_path, vectorizer_path)
    
    # Verify the files were created
    assert os.path.exists(model_path)
    assert os.path.exists(vectorizer_path)
    
    # Load the model
    loaded_model, loaded_vectorizer = load_model(model_path, vectorizer_path)
    
    # Verify the loaded model and vectorizer
    assert loaded_model is not None
    assert loaded_vectorizer is not None

def test_predict_technique():
    """Test predicting a MITRE ATT&CK technique."""
    # Train a model
    model, vectorizer = train_model(TEST_THREAT_OBJECTS)
    
    # Call the function
    result = predict_technique("This is a test technique for phishing attacks", model, vectorizer)
    
    # Verify the result
    assert result is not None

def test_map_mitre_to_stix():
    """Test mapping MITRE ATT&CK IDs to STIX IDs."""
    # Call the function
    result = map_mitre_to_stix(TEST_MITRE_DATA)
    
    # Verify the result
    assert result is not None
    assert isinstance(result, dict)
    assert 'T0001' in result
    assert result['T0001'] == 'attack-pattern--00000000-0000-0000-0000-000000000001'
    assert 'T0002' in result
    assert result['T0002'] == 'attack-pattern--00000000-0000-0000-0000-000000000002'

def test_map_threat_data():
    """Test mapping threat data to MITRE ATT&CK techniques."""
    # Train a model
    model, vectorizer = train_model(TEST_THREAT_OBJECTS)
    
    # Call the function
    result = map_threat_data(TEST_MITRE_DATA, model, vectorizer)
    
    # Verify the result
    assert result is not None
    assert isinstance(result, list)
    assert len(result) > 0
    assert 'threat_id' in result[0]
    assert 'external_id' in result[0]
    assert 'technique_name' in result[0]
    assert 'stix_id' in result[0]

def test_save_mappings_to_file(temp_dir):
    """Test saving mappings to a file."""
    # Define test mappings
    mappings = [
        {
            'threat_id': 'attack-pattern--00000000-0000-0000-0000-000000000001',
            'external_id': 'T0001',
            'technique_name': 'Test Technique 1',
            'stix_id': 'attack-pattern--00000000-0000-0000-0000-000000000001',
            'description': 'This is a test technique for phishing attacks',
            'source': 'MITRE ATT&CK',
            'timestamp': '2023-01-01T00:00:00Z'
        }
    ]
    
    # Define file path
    output_file_path = os.path.join(temp_dir, "data", "processed", "test_mappings.json")
    
    # Call the function
    save_mappings_to_file(mappings, output_file_path)
    
    # Verify the file was created and contains the correct data
    assert os.path.exists(output_file_path)
    with open(output_file_path, 'r') as f:
        saved_mappings = json.load(f)
    assert saved_mappings == mappings

def test_store_mappings_in_db():
    """Test storing mappings in the database."""
    # Define test mappings
    mappings = [
        {
            'threat_id': 'attack-pattern--00000000-0000-0000-0000-000000000001',
            'external_id': 'T0001',
            'technique_name': 'Test Technique 1',
            'stix_id': 'attack-pattern--00000000-0000-0000-0000-000000000001',
            'description': 'This is a test technique for phishing attacks',
            'source': 'MITRE ATT&CK',
            'timestamp': '2023-01-01T00:00:00Z'
        }
    ]
    
    # Mock the SQLAlchemy engine and connection
    with patch('scripts.mapping.consolidated_mapping_algorithm.create_engine') as mock_create_engine:
        # Mock the engine instance
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        
        # Mock the connection
        mock_connection = MagicMock()
        mock_engine.connect.return_value = mock_connection
        
        # Mock the metadata
        mock_metadata = MagicMock()
        with patch('scripts.mapping.consolidated_mapping_algorithm.MetaData') as mock_metadata_class:
            mock_metadata_class.return_value = mock_metadata
            
            # Mock the table
            mock_table = MagicMock()
            mock_metadata.tables = {'mapped_threat_data': mock_table}
            
            # Call the function
            from scripts.mapping.consolidated_mapping_algorithm import store_mappings_in_db
            store_mappings_in_db(mappings, 'postgresql://test:test@localhost/test')
            
            # Verify the connection methods were called
            mock_engine.connect.assert_called_once()
            mock_connection.execute.assert_called()
            mock_connection.close.assert_called_once()

def test_map_threat_data_workflow():
    """Test the end-to-end mapping workflow."""
    # Mock the necessary functions
    with patch('scripts.mapping.consolidated_mapping_algorithm.open', MagicMock()):
        with patch('scripts.mapping.consolidated_mapping_algorithm.json.load') as mock_json_load:
            # Mock the JSON data
            mock_json_load.return_value = TEST_MITRE_DATA
            
            # Mock the model training
            with patch('scripts.mapping.consolidated_mapping_algorithm.train_model') as mock_train_model:
                # Mock the model and vectorizer
                mock_model = MagicMock()
                mock_vectorizer = MagicMock()
                mock_train_model.return_value = (mock_model, mock_vectorizer)
                
                # Mock the mapping function
                with patch('scripts.mapping.consolidated_mapping_algorithm.map_threat_data') as mock_map_threat_data:
                    # Mock the mappings
                    mock_mappings = [
                        {
                            'threat_id': 'attack-pattern--00000000-0000-0000-0000-000000000001',
                            'external_id': 'T0001',
                            'technique_name': 'Test Technique 1',
                            'stix_id': 'attack-pattern--00000000-0000-0000-0000-000000000001'
                        }
                    ]
                    mock_map_threat_data.return_value = mock_mappings
                    
                    # Mock the save functions
                    with patch('scripts.mapping.consolidated_mapping_algorithm.save_mappings_to_file') as mock_save_mappings:
                        with patch('scripts.mapping.consolidated_mapping_algorithm.visualize_mappings') as mock_visualize:
                            with patch('scripts.mapping.consolidated_mapping_algorithm.store_mappings_in_db') as mock_store_mappings:
                                # Call the function
                                from scripts.mapping.consolidated_mapping_algorithm import map_threat_data_workflow
                                map_threat_data_workflow()
                                
                                # Verify the functions were called
                                mock_train_model.assert_called_once()
                                mock_map_threat_data.assert_called_once()
                                mock_save_mappings.assert_called_once()
                                mock_visualize.assert_called_once()
                                mock_store_mappings.assert_called_once()
