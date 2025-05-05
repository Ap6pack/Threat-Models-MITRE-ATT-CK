import os
import yaml
import requests
import logging
import json
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from taxii2client.v20 import Server

# Load the configuration settings from the YAML file
with open('config/settings.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Access specific settings from the YAML config
api_url = config['api_url']
raw_data_path = config['raw_data_path']
log_file_path = config['log_file_path']

# Ensure the logs directory exists
log_dir = os.path.dirname(log_file_path)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Set up logging based on config
logging.basicConfig(filename=log_file_path, level=logging.INFO)

def fetch_mitre_attack_data():
    logging.info("Fetching MITRE ATT&CK data using TAXII...")
    # Fetch data from TAXII
    server = Server('https://cti-taxii.mitre.org/taxii/')
    api_root = server.api_roots[0]
    collection = api_root.collections[0]
    
    # Filter for attack-pattern objects
    attack_patterns = []
    for obj in collection.get_objects()['objects']:
        if obj['type'] == 'attack-pattern':
            attack_patterns.append(obj)
    
    logging.info(f"Fetched {len(attack_patterns)} attack patterns.")
    return {"objects": attack_patterns}

def save_data_to_json(data, file_path):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)
    logging.info(f"Data saved to {file_path}")

def map_mitre_to_stix(mitre_data):
    mitre_to_stix = {}
    for obj in mitre_data['objects']:
        if obj['type'] == 'attack-pattern' and 'external_references' in obj:
            for reference in obj['external_references']:
                if reference['source_name'] == 'mitre-attack':
                    mitre_id = reference['external_id']
                    stix_id = obj['id']
                    mitre_to_stix[mitre_id] = stix_id
    return mitre_to_stix

def train_model(threat_objects):
    # Extract descriptions and labels
    descriptions = [obj['description'] for obj in threat_objects if 'description' in obj]
    labels = [ref['external_id'] for obj in threat_objects for ref in obj.get('external_references', []) if ref['source_name'] == 'mitre-attack']

    # Ensure descriptions and labels are of equal length
    if len(descriptions) != len(labels):
        labels = labels[:len(descriptions)]

    # Train the ML model
    vectorizer = TfidfVectorizer()
    model = MultinomialNB()
    pipeline = make_pipeline(vectorizer, model)
    pipeline.fit(descriptions, labels)
    
    logging.info("Model trained successfully.")
    return pipeline, vectorizer

def predict_technique(description, model, vectorizer):
    return model.predict([description])[0]

def visualize_mappings(mappings):
    df = pd.DataFrame(mappings)
    # Save the mappings CSV file in the data/processed/ directory
    output_path = 'data/processed/mappings.csv'
    df.to_csv(output_path, index=False)
    logging.info(f"Mappings saved to {output_path}")
    print(df)

def update_threat_models():
    # Load MITRE ATT&CK data from JSON file
    with open('data/mitre_attack_data.json') as f:
        threat_data = json.load(f)
    
    threat_objects = threat_data.get('objects', [])

    # Create mapping of MITRE IDs to STIX IDs
    mitre_to_stix = map_mitre_to_stix(threat_data)
    logging.info("MITRE to STIX mapping created.")
    print("MITRE to STIX mapping:")
    print(mitre_to_stix)

    # Train ML model
    model, vectorizer = train_model(threat_objects)

    # Map threats to MITRE ATT&CK using enhanced methods
    mappings = []
    for threat in threat_objects:
        if 'description' in threat:
            external_id = predict_technique(threat['description'], model, vectorizer)
            stix_id = mitre_to_stix.get(external_id)
            if stix_id:
                technique_name = next((obj['name'] for obj in threat_objects if obj['id'] == stix_id), None)
                mappings.append({
                    'threat_id': threat['id'],
                    'external_id': external_id,
                    'technique_name': technique_name,
                    'stix_id': stix_id
                })

    logging.info(f"Processed {len(mappings)} mappings.")
    visualize_mappings(mappings)

if __name__ == "__main__":
    # Fetch the MITRE ATT&CK data and save it
    mitre_data = fetch_mitre_attack_data()
    save_data_to_json(mitre_data, 'data/mitre_attack_data.json')

    # Update the threat models based on the fetched data
    update_threat_models()
