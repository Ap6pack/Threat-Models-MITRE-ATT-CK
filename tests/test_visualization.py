import unittest
import os
import sys
import pandas as pd
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import numpy as np
import json
from unittest.mock import patch, MagicMock

# Add the project root to the path so we can import the modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import modules to test
from scripts.visualization.consolidated_dashboard import (
    fetch_data_from_db, 
    fetch_data_from_file,
    create_interactive_map,
    plot_threat_types,
    plot_threats_over_time,
    generate_static_visualizations
)

class TestVisualization(unittest.TestCase):
    """Test suite for visualization components"""

    def setUp(self):
        """Set up test fixtures, if any."""
        # Create a sample DataFrame for testing
        self.test_data = pd.DataFrame({
            'id': range(1, 11),
            'threat_id': [f'T{i}' for i in range(1, 11)],
            'technique_id': ['T1001', 'T1002', 'T1003', 'T1001', 'T1002', 
                           'T1004', 'T1005', 'T1001', 'T1002', 'T1003'],
            'description': [f'Description {i}' for i in range(1, 11)],
            'source': ['MITRE ATT&CK', 'AlienVault OTX', 'VirusTotal', 'MITRE ATT&CK', 
                      'AlienVault OTX', 'MITRE ATT&CK', 'VirusTotal', 'AlienVault OTX', 
                      'MITRE ATT&CK', 'VirusTotal'],
            'timestamp': [datetime.now() - timedelta(days=i) for i in range(10)],
            'technique_name': ['Data Obfuscation', 'System Information Discovery', 
                             'Account Discovery', 'Data Obfuscation', 
                             'System Information Discovery', 'Data Manipulation', 
                             'Process Discovery', 'Data Obfuscation', 
                             'System Information Discovery', 'Account Discovery'],
            'tactic_name': ['Defense Evasion', 'Discovery', 'Discovery', 
                          'Defense Evasion', 'Discovery', 'Impact', 
                          'Discovery', 'Defense Evasion', 'Discovery', 'Discovery'],
            'tactic_id': ['TA0005', 'TA0007', 'TA0007', 'TA0005', 'TA0007', 
                        'TA0040', 'TA0007', 'TA0005', 'TA0007', 'TA0007'],
            'latitude': [random * 180 - 90 for random in np.random.random(10)],
            'longitude': [random * 360 - 180 for random in np.random.random(10)]
        })
        
        # Create temporary test directory
        os.makedirs('test_data', exist_ok=True)
        os.makedirs('test_reports', exist_ok=True)
        
        # Save test data to file
        self.test_file_path = 'test_data/test_threat_data.json'
        with open(self.test_file_path, 'w') as f:
            json.dump(self.test_data.to_dict('records'), f)

    def tearDown(self):
        """Tear down test fixtures, if any."""
        # Remove test files
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)
        
        # Remove test directories
        for dir_path in ['test_data', 'test_reports']:
            try:
                os.rmdir(dir_path)
            except OSError:
                # Directory not empty, leave it
                pass
        
        # Close any open figures
        plt.close('all')

    @patch('scripts.visualization.consolidated_dashboard.create_engine')
    def test_fetch_data_from_db(self, mock_create_engine):
        """Test fetching data from database"""
        # Create a mock for the database connection
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        
        # Mock the read_sql_query function to return our test data
        mock_engine.connect.return_value.__enter__.return_value.execute.return_value = self.test_data
        pd.read_sql_query = MagicMock(return_value=self.test_data)
        
        # Call the function
        result = fetch_data_from_db()
        
        # Check that create_engine was called
        mock_create_engine.assert_called_once()
        
        # Basic check on results
        self.assertIsInstance(result, pd.DataFrame)
        self.assertEqual(len(result), len(self.test_data))

    def test_fetch_data_from_file(self):
        """Test fetching data from file"""
        # Call the function with our test file
        result = fetch_data_from_file(self.test_file_path)
        
        # Check the result
        self.assertIsInstance(result, pd.DataFrame)
        self.assertEqual(len(result), len(self.test_data))
        
        # Test with non-existent file
        result = fetch_data_from_file('non_existent_file.json')
        self.assertTrue(result.empty)

    def test_create_interactive_map(self):
        """Test creation of interactive map"""
        # Set output path for test
        output_path = 'test_reports/test_map.html'
        
        # Call the function
        create_interactive_map(self.test_data, output_path)
        
        # Check that the file was created
        self.assertTrue(os.path.exists(output_path))
        
        # Clean up
        if os.path.exists(output_path):
            os.remove(output_path)
        
        # Test with data missing location information
        data_no_location = self.test_data.drop(columns=['latitude', 'longitude'])
        result = create_interactive_map(data_no_location, output_path)
        self.assertFalse(os.path.exists(output_path))

    def test_plot_threat_types(self):
        """Test creation of threat types chart"""
        # Set output path for test
        output_path = 'test_reports/test_threat_types.png'
        
        # Call the function
        plot_threat_types(self.test_data, output_path)
        
        # Check that the file was created
        self.assertTrue(os.path.exists(output_path))
        
        # Clean up
        if os.path.exists(output_path):
            os.remove(output_path)
        
        # Test with data missing technique_name
        data_no_technique = self.test_data.drop(columns=['technique_name'])
        plot_threat_types(data_no_technique, output_path)
        self.assertFalse(os.path.exists(output_path))

    def test_plot_threats_over_time(self):
        """Test creation of threats over time chart"""
        # Set output path for test
        output_path = 'test_reports/test_threats_over_time.png'
        
        # Call the function
        plot_threats_over_time(self.test_data, output_path)
        
        # Check that the file was created
        self.assertTrue(os.path.exists(output_path))
        
        # Clean up
        if os.path.exists(output_path):
            os.remove(output_path)
        
        # Test with data missing timestamp
        data_no_timestamp = self.test_data.drop(columns=['timestamp'])
        plot_threats_over_time(data_no_timestamp, output_path)
        self.assertFalse(os.path.exists(output_path))

    @patch('scripts.visualization.consolidated_dashboard.fetch_data_from_db')
    @patch('scripts.visualization.consolidated_dashboard.fetch_data_from_file')
    @patch('scripts.visualization.consolidated_dashboard.create_interactive_map')
    @patch('scripts.visualization.consolidated_dashboard.plot_threat_types')
    @patch('scripts.visualization.consolidated_dashboard.plot_threats_over_time')
    def test_generate_static_visualizations(self, mock_plot_time, mock_plot_types, 
                                           mock_create_map, mock_fetch_file, mock_fetch_db):
        """Test the full visualization generation process"""
        # Set up mocks
        mock_fetch_db.return_value = self.test_data
        mock_fetch_file.return_value = pd.DataFrame()  # Should not be called if DB has data
        
        # Call the function
        generate_static_visualizations()
        
        # Verify the calls
        mock_fetch_db.assert_called_once()
        mock_fetch_file.assert_not_called()
        mock_create_map.assert_called_once()
        mock_plot_types.assert_called_once()
        mock_plot_time.assert_called_once()
        
        # Now test the fallback to file
        mock_fetch_db.return_value = pd.DataFrame()  # Empty DataFrame
        mock_fetch_file.return_value = self.test_data
        
        # Reset mocks
        mock_create_map.reset_mock()
        mock_plot_types.reset_mock()
        mock_plot_time.reset_mock()
        
        # Call the function again
        generate_static_visualizations()
        
        # Verify the calls
        mock_fetch_db.assert_called()
        mock_fetch_file.assert_called_once()
        mock_create_map.assert_called_once()
        mock_plot_types.assert_called_once()
        mock_plot_time.assert_called_once()
        
        # Test with no data
        mock_fetch_db.return_value = pd.DataFrame()
        mock_fetch_file.return_value = pd.DataFrame()
        
        # Reset mocks
        mock_create_map.reset_mock()
        mock_plot_types.reset_mock()
        mock_plot_time.reset_mock()
        
        # Call the function again
        generate_static_visualizations()
        
        # Verify no visualization functions were called
        mock_create_map.assert_not_called()
        mock_plot_types.assert_not_called()
        mock_plot_time.assert_not_called()

if __name__ == '__main__':
    unittest.main()
