import os
import json
import logging
import yaml
import psycopg2
from psycopg2 import sql
import uuid
from sqlalchemy import create_engine, Table, MetaData, Column, String, Text, JSON, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Load configuration
with open('config/settings.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Database configuration
db_config = config.get('database', {
    'dbname': 'threat_intelligence',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432'
})

# Set up logging
logging.basicConfig(filename='logs/app.log', level=logging.INFO)

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine(f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['dbname']}")
Session = sessionmaker(bind=engine)

# Define SQLAlchemy models
class MitreAttackTechnique(Base):
    __tablename__ = 'mitre_attack_techniques'
    
    mitre_attack_id = Column(String, primary_key=True)
    technique_name = Column(String, nullable=False)
    description = Column(Text)
    tactic = Column(String)
    tactic_name = Column(String)  # Added for visualization
    tactic_id = Column(String)    # Added for visualization
    platform = Column(String)     # Added for visualization
    data_sources = Column(String) # Added for visualization
    is_subtechnique = Column(String) # Added for visualization
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

class ThreatIntelligenceData(Base):
    __tablename__ = 'threat_intelligence_data'
    
    threat_id = Column(String, primary_key=True)
    threat_name = Column(String, nullable=False)
    description = Column(Text)
    mitre_attack_id = Column(String)
    source = Column(String)
    timestamp = Column(DateTime, default=datetime.now)
    additional_info = Column(JSON)

class OtxData(Base):
    __tablename__ = 'otx_data'
    
    id = Column(String, primary_key=True)
    indicator_type = Column(String)
    indicator_value = Column(String)
    description = Column(Text)
    source = Column(String)
    timestamp = Column(DateTime, default=datetime.now)
    additional_info = Column(JSON)

class VirusTotalData(Base):
    __tablename__ = 'virustotal_data'
    
    id = Column(String, primary_key=True)
    event_id = Column(String)
    description = Column(Text)
    severity = Column(String)
    source = Column(String)
    timestamp = Column(DateTime, default=datetime.now)
    additional_info = Column(JSON)

class MappedThreatData(Base):
    __tablename__ = 'mapped_threat_data'
    
    id = Column(String, primary_key=True)
    threat_id = Column(String)
    technique_id = Column(String)
    description = Column(Text)
    source = Column(String)
    timestamp = Column(DateTime, default=datetime.now)

def create_tables():
    """
    Create database tables if they don't exist.
    """
    try:
        # Drop existing tables to ensure schema is up-to-date
        Base.metadata.drop_all(engine)
        
        # Create tables with the updated schema
        Base.metadata.create_all(engine)
        logging.info("Database tables created successfully")
    except Exception as e:
        logging.error(f"Error creating database tables: {str(e)}")

def store_mitre_attack_data(data_file_path):
    """
    Store MITRE ATT&CK data in the database.
    
    Args:
        data_file_path: Path to the normalized MITRE ATT&CK data JSON file
    """
    logging.info(f"Storing MITRE ATT&CK data from {data_file_path}")
    
    try:
        # Load the normalized data
        with open(data_file_path, 'r') as f:
            normalized_data = json.load(f)
        
        session = Session()
        
        # Process each technique
        for technique in normalized_data:
            # Extract tactics as a comma-separated string
            tactics_str = ", ".join(technique.get('tactics', []))
            
            # Create or update the technique in the database
            db_technique = MitreAttackTechnique(
                mitre_attack_id=technique.get('mitre_id', str(uuid.uuid4())),
                technique_name=technique.get('name', 'Unknown Technique'),
                description=technique.get('description', ''),
                tactic=tactics_str,
                tactic_name=technique.get('tactics', ['Unknown'])[0] if technique.get('tactics') else 'Unknown',
                tactic_id=technique.get('tactic_id', ''),
                platform=','.join(technique.get('platforms', [])) if technique.get('platforms') else '',
                data_sources=','.join(technique.get('data_sources', [])) if technique.get('data_sources') else '',
                is_subtechnique=str('.' in technique.get('mitre_id', ''))
            )
            
            # Add to session (will be inserted or updated)
            session.merge(db_technique)
        
        # Commit the changes
        session.commit()
        logging.info(f"Stored {len(normalized_data)} MITRE ATT&CK techniques in the database")
    
    except Exception as e:
        logging.error(f"Error storing MITRE ATT&CK data: {str(e)}")
    finally:
        session.close()

def store_otx_data(data_file_path):
    """
    Store AlienVault OTX data in the database.
    
    Args:
        data_file_path: Path to the normalized OTX data JSON file
    """
    logging.info(f"Storing OTX data from {data_file_path}")
    
    try:
        # Load the normalized data
        with open(data_file_path, 'r') as f:
            normalized_data = json.load(f)
        
        session = Session()
        
        # Process each indicator
        for indicator in normalized_data:
            # Create timestamp object from string
            timestamp = datetime.fromisoformat(indicator.get('timestamp').replace('Z', '+00:00')) if 'timestamp' in indicator else datetime.now()
            
            # Create or update the indicator in the database
            # Ensure ID is always a string
            indicator_id = indicator.get('id')
            if indicator_id is not None:
                indicator_id = str(indicator_id)
            else:
                indicator_id = str(uuid.uuid4())
                
            db_indicator = OtxData(
                id=indicator_id,
                indicator_type=indicator.get('indicator_type', 'unknown'),
                indicator_value=indicator.get('indicator_value', ''),
                description=indicator.get('description', ''),
                source=indicator.get('source', 'AlienVault OTX'),
                timestamp=timestamp,
                additional_info=indicator
            )
            
            # Add to session (will be inserted or updated)
            session.merge(db_indicator)
        
        # Commit the changes
        session.commit()
        logging.info(f"Stored {len(normalized_data)} OTX indicators in the database")
    
    except Exception as e:
        logging.error(f"Error storing OTX data: {str(e)}")
    finally:
        session.close()

def store_vt_data(data_file_path):
    """
    Store VirusTotal data in the database.
    
    Args:
        data_file_path: Path to the normalized VirusTotal data JSON file
    """
    logging.info(f"Storing VirusTotal data from {data_file_path}")
    
    try:
        # Load the normalized data
        with open(data_file_path, 'r') as f:
            normalized_data = json.load(f)
        
        session = Session()
        
        # Process each notification
        for notification in normalized_data:
            # Create timestamp object from string
            timestamp = datetime.fromisoformat(notification.get('timestamp').replace('Z', '+00:00')) if 'timestamp' in notification else datetime.now()
            
            # Create or update the notification in the database
            # Ensure ID is always a string
            notification_id = notification.get('id')
            if notification_id is not None:
                notification_id = str(notification_id)
            else:
                notification_id = str(uuid.uuid4())
                
            db_notification = VirusTotalData(
                id=notification_id,
                event_id=str(notification.get('id', '')),
                description=notification.get('description', ''),
                severity=str(notification.get('severity', 0)),
                source=notification.get('source', 'VirusTotal'),
                timestamp=timestamp,
                additional_info=notification
            )
            
            # Add to session (will be inserted or updated)
            session.merge(db_notification)
        
        # Commit the changes
        session.commit()
        logging.info(f"Stored {len(normalized_data)} VirusTotal notifications in the database")
    
    except Exception as e:
        logging.error(f"Error storing VirusTotal data: {str(e)}")
    finally:
        session.close()

def store_mapped_data(data_file_path):
    """
    Store mapped threat data in the database.
    
    Args:
        data_file_path: Path to the mapped threat data JSON file
    """
    logging.info(f"Storing mapped threat data from {data_file_path}")
    
    try:
        # Load the mapped data
        with open(data_file_path, 'r') as f:
            mapped_data = json.load(f)
        
        session = Session()
        
        # Process each mapping
        for mapping in mapped_data:
            # Create or update the mapping in the database
            db_mapping = MappedThreatData(
                id=str(uuid.uuid4()),
                threat_id=mapping.get('threat_id', ''),
                technique_id=mapping.get('technique_id', ''),
                description=mapping.get('description', ''),
                source=mapping.get('source', 'Unknown'),
                timestamp=datetime.now()
            )
            
            # Add to session
            session.add(db_mapping)
        
        # Commit the changes
        session.commit()
        logging.info(f"Stored {len(mapped_data)} mapped threats in the database")
    
    except Exception as e:
        logging.error(f"Error storing mapped threat data: {str(e)}")
    finally:
        session.close()

def store_all_data():
    """
    Store all normalized and mapped data in the database.
    """
    # Create tables if they don't exist
    create_tables()
    
    # Define file paths
    norm_mitre_path = 'data/processed/normalized_mitre_data.json'
    norm_otx_path = 'data/processed/normalized_otx_data.json'
    norm_vt_path = 'data/processed/normalized_vt_data.json'
    mapped_data_path = 'data/processed/mapped_threat_data.json'
    
    # Store data from each source
    if os.path.exists(norm_mitre_path):
        store_mitre_attack_data(norm_mitre_path)
    
    if os.path.exists(norm_otx_path):
        store_otx_data(norm_otx_path)
    
    if os.path.exists(norm_vt_path):
        store_vt_data(norm_vt_path)
    
    if os.path.exists(mapped_data_path):
        store_mapped_data(mapped_data_path)
    
    logging.info("All data stored in the database")

if __name__ == "__main__":
    store_all_data()
