import unittest
import os
import sys
import json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from second.scripts.data_ingestion.normalize_data import normalize_data, save_normalized_data

class TestDataNormalization(unittest.TestCase):

    def setUp(self):
        # Prepare sample raw data for testing normalization
        self.raw_data = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "AutoHotKey & AutoIT",
                    "description": "The adversary attempts to make an operation more difficult to detect.",
                    "kill_chain_phases": [
                        {"phase_name": "execution"}
                    ],
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1059.010"}
                    ],
                    "x_mitre_platforms": ["Windows"],
                    "x_mitre_data_sources": [
                        "Process: Process Creation", "Command: Command Execution"
                    ],
                    "x_mitre_is_subtechnique": True
                }
            ]
        }
        self.test_processed_path = 'data/processed/test_normalized_data.json'
        os.makedirs(os.path.dirname(self.test_processed_path), exist_ok=True)

    def tearDown(self):
        # Clean up test files after the test
        if os.path.exists(self.test_processed_path):
            os.remove(self.test_processed_path)
        
    def test_normalize_data(self):
        # Test if the data normalization works as expected
        normalized_data = normalize_data(self.raw_data)
        self.assertEqual(len(normalized_data), 1)
        self.assertEqual(normalized_data[0]['technique_id'], 'T1059.010')  # Expect T1059.010 (the correct ID from raw data)
        self.assertEqual(normalized_data[0]['technique_name'], 'AutoHotKey & AutoIT')
        self.assertEqual(normalized_data[0]['tactic'], 'execution')
        self.assertEqual(normalized_data[0]['platforms'], ['Windows'])
        self.assertEqual(normalized_data[0]['data_sources'], ['Process: Process Creation', 'Command: Command Execution'])
        self.assertEqual(normalized_data[0]['is_subtechnique'], True)

    def test_save_normalized_data(self):
        # Test if normalized data is saved correctly
        normalized_data = normalize_data(self.raw_data)
        save_normalized_data(normalized_data, file_path=self.test_processed_path)

        # Check if the file is saved and content is correct
        self.assertTrue(os.path.exists(self.test_processed_path))
        with open(self.test_processed_path, 'r') as file:
            saved_data = json.load(file)
            self.assertEqual(saved_data[0]['technique_id'], 'T1059.010')  # Expect T1059.010 here as well

if __name__ == "__main__":
    unittest.main()