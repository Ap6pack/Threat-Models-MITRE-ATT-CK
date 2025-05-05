import os
import json
import logging
import pandas as pd
from datetime import datetime

# Set up logging
logging.basicConfig(filename='logs/app.log', level=logging.INFO)

def normalize_mitre_data(input_file_path, output_file_path):
    """
    Normalize MITRE ATT&CK data into a consistent format.
    
    Args:
        input_file_path: Path to the raw MITRE ATT&CK data JSON file
        output_file_path: Path to save the normalized data
    """
    logging.info(f"Normalizing MITRE ATT&CK data from {input_file_path}")
    
    try:
        # Load the raw data
        with open(input_file_path, 'r') as f:
            raw_data = json.load(f)
        
        normalized_data = []
        
        # Process each attack pattern
        for obj in raw_data.get('objects', []):
            if obj['type'] == 'attack-pattern':
                # Extract MITRE ATT&CK ID from external references
                mitre_id = None
                for ref in obj.get('external_references', []):
                    if ref.get('source_name') == 'mitre-attack':
                        mitre_id = ref.get('external_id')
                        break
                
                # Extract tactics (kill chain phases)
                tactics = []
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactics.append(phase.get('phase_name'))
                
                # Extract platforms
                platforms = obj.get('x_mitre_platforms', [])
                
                # Extract data sources
                data_sources = obj.get('x_mitre_data_sources', [])
                
                # Determine if it's a sub-technique
                is_subtechnique = '.' in mitre_id if mitre_id else False
                
                # Extract tactic IDs
                tactic_ids = []
                for phase in obj.get('kill_chain_phases', []):
                    if phase.get('kill_chain_name') == 'mitre-attack':
                        tactic_id = phase.get('phase_name')
                        if tactic_id:
                            tactic_ids.append(tactic_id)
                
                # Create normalized entry with additional fields
                normalized_entry = {
                    'id': obj.get('id'),
                    'mitre_id': mitre_id,
                    'name': obj.get('name'),
                    'description': obj.get('description'),
                    'tactics': tactics,
                    'tactic_id': tactic_ids[0] if tactic_ids else '',
                    'platforms': platforms,
                    'data_sources': data_sources,
                    'is_subtechnique': is_subtechnique,
                    'source': 'MITRE ATT&CK',
                    'timestamp': datetime.now().isoformat()
                }
                
                normalized_data.append(normalized_entry)
        
        # Save normalized data
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, 'w') as f:
            json.dump(normalized_data, f, indent=4)
        
        logging.info(f"Normalized {len(normalized_data)} MITRE ATT&CK techniques to {output_file_path}")
        return normalized_data
    
    except Exception as e:
        logging.error(f"Error normalizing MITRE ATT&CK data: {str(e)}")
        return []

def normalize_otx_data(input_file_path, output_file_path):
    """
    Normalize AlienVault OTX data into a consistent format.
    
    Args:
        input_file_path: Path to the raw OTX data JSON file
        output_file_path: Path to save the normalized data
    """
    logging.info(f"Normalizing OTX data from {input_file_path}")
    
    try:
        # Load the raw data
        with open(input_file_path, 'r') as f:
            raw_data = json.load(f)
        
        normalized_data = []
        
        # Process each indicator
        for item in raw_data:
            normalized_entry = {
                'id': item.get('id', f"otx-{len(normalized_data)}"),
                'indicator_type': item.get('indicator_type', 'unknown'),
                'indicator_value': item.get('indicator', ''),
                'description': item.get('description', ''),
                'source': 'AlienVault OTX',
                'timestamp': item.get('timestamp', datetime.now().isoformat())
            }
            
            normalized_data.append(normalized_entry)
        
        # Save normalized data
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, 'w') as f:
            json.dump(normalized_data, f, indent=4)
        
        logging.info(f"Normalized {len(normalized_data)} OTX indicators to {output_file_path}")
        return normalized_data
    
    except Exception as e:
        logging.error(f"Error normalizing OTX data: {str(e)}")
        return []

def normalize_vt_data(input_file_path, output_file_path):
    """
    Normalize VirusTotal data into a consistent format.
    
    Args:
        input_file_path: Path to the raw VirusTotal data JSON file
        output_file_path: Path to save the normalized data
    """
    logging.info(f"Normalizing VirusTotal data from {input_file_path}")
    
    try:
        # Load the raw data
        with open(input_file_path, 'r') as f:
            raw_data = json.load(f)
        
        normalized_data = []
        
        # Process each notification
        for item in raw_data:
            normalized_entry = {
                'id': item.get('id', f"vt-{len(normalized_data)}"),
                'threat_type': item.get('type', 'unknown'),
                'description': item.get('attributes', {}).get('description', ''),
                'severity': item.get('attributes', {}).get('severity', 0),
                'source': 'VirusTotal',
                'timestamp': item.get('timestamp', datetime.now().isoformat())
            }
            
            normalized_data.append(normalized_entry)
        
        # Save normalized data
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, 'w') as f:
            json.dump(normalized_data, f, indent=4)
        
        logging.info(f"Normalized {len(normalized_data)} VirusTotal notifications to {output_file_path}")
        return normalized_data
    
    except Exception as e:
        logging.error(f"Error normalizing VirusTotal data: {str(e)}")
        return []

def combine_normalized_data(normalized_data_files, output_file_path):
    """
    Combine normalized data from multiple sources into a single file.
    
    Args:
        normalized_data_files: List of paths to normalized data files
        output_file_path: Path to save the combined data
    """
    logging.info(f"Combining normalized data from {len(normalized_data_files)} sources")
    
    combined_data = []
    
    try:
        # Load and combine data from each file
        for file_path in normalized_data_files:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                combined_data.extend(data)
        
        # Save combined data
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, 'w') as f:
            json.dump(combined_data, f, indent=4)
        
        logging.info(f"Combined {len(combined_data)} entries to {output_file_path}")
        return combined_data
    
    except Exception as e:
        logging.error(f"Error combining normalized data: {str(e)}")
        return []

def normalize_all_data():
    """
    Normalize data from all sources and combine them.
    """
    # Define file paths
    raw_mitre_path = 'data/raw/mitre_attack_data.json'
    raw_otx_path = 'data/raw/otx_attack_data.json'
    raw_vt_path = 'data/raw/vt_attack_data.json'
    
    norm_mitre_path = 'data/processed/normalized_mitre_data.json'
    norm_otx_path = 'data/processed/normalized_otx_data.json'
    norm_vt_path = 'data/processed/normalized_vt_data.json'
    
    combined_path = 'data/processed/combined_threat_data.json'
    
    # Normalize each data source
    normalized_files = []
    
    if os.path.exists(raw_mitre_path):
        normalize_mitre_data(raw_mitre_path, norm_mitre_path)
        normalized_files.append(norm_mitre_path)
    
    if os.path.exists(raw_otx_path):
        normalize_otx_data(raw_otx_path, norm_otx_path)
        normalized_files.append(norm_otx_path)
    
    if os.path.exists(raw_vt_path):
        normalize_vt_data(raw_vt_path, norm_vt_path)
        normalized_files.append(norm_vt_path)
    
    # Combine normalized data
    if normalized_files:
        combine_normalized_data(normalized_files, combined_path)
    
    logging.info("Data normalization completed")

if __name__ == "__main__":
    normalize_all_data()
