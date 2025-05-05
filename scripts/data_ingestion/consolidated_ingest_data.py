import os
import yaml
import requests
import logging
import json
import pandas as pd
import uuid
from datetime import datetime
from taxii2client.v20 import Server
from stix2 import TAXIICollectionSource, Filter
from taxii2client.v20 import Collection

# Load the configuration settings from the YAML file
with open('config/settings.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Access specific settings from the YAML config
api_url = config.get('api_url', 'https://attack-taxii.mitre.org/api/v21/')
mitre_attack_url = config.get('mitre_attack_url', 'https://attack-taxii.mitre.org/api/v21/collections/')
raw_data_path = config.get('raw_data_path', 'data/raw/mitre_attack_data.json')
log_file_path = config.get('log_file_path', 'logs/app.log')
otx_api_key = config.get('otx_api_key', '')
vt_api_key = config.get('vt_api_key', '')

# Ensure the logs directory exists
log_dir = os.path.dirname(log_file_path)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Set up logging based on config
logging.basicConfig(filename=log_file_path, level=logging.INFO)

def fetch_mitre_attack_data():
    """
    Fetch MITRE ATT&CK data using TAXII protocol.
    Returns a dictionary with 'objects' key containing attack patterns.
    """
    logging.info("Fetching MITRE ATT&CK data using TAXII...")
    try:
        # Try to fetch data from TAXII server
        try:
            import requests
            
            # First, get the list of collections
            headers = {
                "Accept": "application/taxii+json;version=2.1"
            }
            
            # Get collections
            collections_url = mitre_attack_url
            collections_response = requests.get(collections_url, headers=headers)
            
            if collections_response.status_code != 200:
                raise Exception(f"Failed to get collections: {collections_response.status_code} - {collections_response.text}")
            
            collections_data = collections_response.json()
            collections = collections_data.get('collections', [])
            
            if not collections:
                raise Exception("No collections found in TAXII server")
            
            # Find Enterprise ATT&CK collection
            enterprise_collection = None
            for collection in collections:
                if "Enterprise ATT&CK" in collection.get('title', ''):
                    enterprise_collection = collection
                    break
            
            if not enterprise_collection:
                # If Enterprise collection not found, use the first available collection
                enterprise_collection = collections[0]
            
            # Get objects from collection
            collection_id = enterprise_collection.get('id')
            objects_url = f"{mitre_attack_url}{collection_id}/objects/"
            
            objects_response = requests.get(objects_url, headers=headers)
            
            if objects_response.status_code != 200:
                raise Exception(f"Failed to get objects: {objects_response.status_code} - {objects_response.text}")
            
            objects_data = objects_response.json()
            
            # Filter for attack-pattern objects
            attack_patterns = []
            for obj in objects_data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    attack_patterns.append(obj)
            
            logging.info(f"Fetched {len(attack_patterns)} attack patterns from TAXII server.")
            return {"objects": attack_patterns}
            
        except Exception as taxii_error:
            logging.warning(f"Could not fetch from TAXII server: {str(taxii_error)}. Using example data instead.")
            
            # Use example threat data as a fallback
            with open('data/raw/example_threat_data.json', 'r') as f:
                example_data = json.load(f)
            
            # Convert example data to STIX format
            attack_patterns = []
            for item in example_data:
                # Create a STIX attack-pattern object from example data
                attack_pattern = {
                    "id": f"attack-pattern--{item['id'].lower()}",
                    "type": "attack-pattern",
                    "name": f"Example: {item['description']}",
                    "description": item['description'],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": item['id']
                        }
                    ],
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "execution"
                        }
                    ]
                }
                attack_patterns.append(attack_pattern)
            
            logging.info(f"Using {len(attack_patterns)} example attack patterns as fallback.")
            return {"objects": attack_patterns}
            
    except Exception as e:
        logging.error(f"Error in fetch_mitre_attack_data: {str(e)}")
        return {"objects": []}

def fetch_otx_attack_data():
    """
    Fetch threat data from AlienVault OTX.
    Returns a list of threat indicators.
    """
    if not otx_api_key:
        logging.warning("OTX API key not provided. Skipping OTX data fetch.")
        return []
    
    logging.info("Fetching data from AlienVault OTX...")
    try:
        # Use the pulse API endpoint instead of indicators/export
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        headers = {"X-OTX-API-KEY": otx_api_key}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            response_data = response.json()
            results = response_data.get('results', [])
            
            # Process the data into a consistent format
            processed_data = []
            for pulse in results:
                # Extract indicators from each pulse
                for indicator in pulse.get('indicators', []):
                    indicator_data = {
                        'id': indicator.get('id', str(uuid.uuid4())),
                        'type': indicator.get('type', 'unknown'),
                        'indicator': indicator.get('indicator', ''),
                        'description': pulse.get('description', ''),
                        'name': pulse.get('name', ''),
                        'author': pulse.get('author_name', ''),
                        'created': pulse.get('created', ''),
                        'source': 'AlienVault OTX',
                        'timestamp': datetime.now().isoformat()
                    }
                    processed_data.append(indicator_data)
            
            logging.info(f"Fetched {len(processed_data)} indicators from OTX.")
            return processed_data
        else:
            logging.error(f"Error fetching data from OTX: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        logging.error(f"Exception fetching OTX data: {str(e)}")
        return []

def fetch_vt_attack_data():
    """
    Fetch threat data from VirusTotal.
    Returns a list of threat notifications.
    """
    if not vt_api_key:
        logging.warning("VirusTotal API key not provided. Skipping VT data fetch.")
        return []
    
    logging.info("Fetching data from VirusTotal...")
    try:
        # Use a different endpoint that doesn't require Intelligence subscription
        url = "https://www.virustotal.com/api/v3/domains/suspicious"
        headers = {"x-apikey": vt_api_key}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            response_data = response.json()
            data = response_data.get('data', [])
            
            # Process the data into a consistent format
            processed_data = []
            for item in data:
                attributes = item.get('attributes', {})
                
                # Create a standardized threat entry
                threat_data = {
                    'id': item.get('id', str(uuid.uuid4())),
                    'type': 'domain',
                    'domain': attributes.get('id', ''),
                    'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                    'reputation': attributes.get('reputation', 0),
                    'total_votes': attributes.get('total_votes', {}),
                    'source': 'VirusTotal',
                    'timestamp': datetime.now().isoformat()
                }
                processed_data.append(threat_data)
            
            logging.info(f"Fetched {len(processed_data)} suspicious domains from VirusTotal.")
            return processed_data
        else:
            # Try an alternative endpoint if the first one fails
            url = "https://www.virustotal.com/api/v3/search?query=type:file p:10"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                response_data = response.json()
                data = response_data.get('data', [])
                
                # Process the data into a consistent format
                processed_data = []
                for item in data:
                    attributes = item.get('attributes', {})
                    
                    # Create a standardized threat entry
                    threat_data = {
                        'id': item.get('id', str(uuid.uuid4())),
                        'type': 'file',
                        'name': attributes.get('meaningful_name', ''),
                        'sha256': attributes.get('sha256', ''),
                        'last_analysis_stats': attributes.get('last_analysis_stats', {}),
                        'source': 'VirusTotal',
                        'timestamp': datetime.now().isoformat()
                    }
                    processed_data.append(threat_data)
                
                logging.info(f"Fetched {len(processed_data)} malicious files from VirusTotal.")
                return processed_data
            else:
                logging.error(f"Error fetching data from VirusTotal: {response.status_code} - {response.text}")
                return []
    except Exception as e:
        logging.error(f"Exception fetching VirusTotal data: {str(e)}")
        return []

def save_data_to_json(data, file_path):
    """
    Save data to a JSON file.
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=4)
    logging.info(f"Data saved to {file_path}")

def fetch_and_save_all_data():
    """
    Fetch data from all sources and save to respective files.
    """
    # Fetch and save MITRE ATT&CK data
    mitre_data = fetch_mitre_attack_data()
    mitre_file_path = os.path.join('data/raw', 'mitre_attack_data.json')
    save_data_to_json(mitre_data, mitre_file_path)
    
    # Fetch and save OTX data
    otx_data = fetch_otx_attack_data()
    if otx_data:
        otx_file_path = os.path.join('data/raw', 'otx_attack_data.json')
        save_data_to_json(otx_data, otx_file_path)
    
    # Fetch and save VirusTotal data
    vt_data = fetch_vt_attack_data()
    if vt_data:
        vt_file_path = os.path.join('data/raw', 'vt_attack_data.json')
        save_data_to_json(vt_data, vt_file_path)
    
    logging.info("All data fetched and saved successfully.")

if __name__ == "__main__":
    fetch_and_save_all_data()
