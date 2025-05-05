import os
import sys
import json
import logging
import unittest
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from second.scripts.data_ingestion.ingest_data import fetch_mitre_attack_data, save_data_to_json


class TestDataIngestion(unittest.TestCase):

    def setUp(self):
        # Create a test directory and test log path
        self.test_raw_data_path = 'data/raw/test_mitre_attack_data.json'
        self.test_log_file = 'logs/test_app.log'

        # Ensure the directories exist
        os.makedirs(os.path.dirname(self.test_raw_data_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.test_log_file), exist_ok=True)

    def tearDown(self):
        # Clean up the test files after tests are done
        if os.path.exists(self.test_raw_data_path):
            os.remove(self.test_raw_data_path)
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)

    def test_fetch_mitre_attack_data(self):
        # Test if data is fetched correctly from MITRE ATT&CK API
        data = fetch_mitre_attack_data()
        self.assertIsInstance(data, dict)
        self.assertIn('objects', data)
        self.assertGreater(len(data['objects']), 0)

    def test_save_data_to_json(self):
        # Test if the data is saved correctly to JSON
        data = {"test_key": "test_value"}
        save_data_to_json(data, file_path=self.test_raw_data_path)

        # Check if the file is saved and the content is correct
        self.assertTrue(os.path.exists(self.test_raw_data_path))
        with open(self.test_raw_data_path, 'r') as file:
            saved_data = json.load(file)
            self.assertEqual(saved_data, data)

    def test_log_file_creation(self):
        # Ensure the logs directory exists before setting up the logger
        os.makedirs(os.path.dirname(self.test_log_file), exist_ok=True)

        # Clear any existing handlers and configure logging
        logging.basicConfig(filename=self.test_log_file, level=logging.INFO, force=True)

        # Log a test entry
        logging.info("Test log entry")

        # Check if the log file is created
        self.assertTrue(os.path.exists(self.test_log_file))

        # Check if the log contains the expected log entry
        with open(self.test_log_file, 'r') as log_file:
            log_contents = log_file.read()
            self.assertIn("Test log entry", log_contents)

        # Explicitly close and remove the logging handlers
        for handler in logging.root.handlers[:]:
            handler.close()
            logging.root.removeHandler(handler)        

if __name__ == "__main__":
    unittest.main()