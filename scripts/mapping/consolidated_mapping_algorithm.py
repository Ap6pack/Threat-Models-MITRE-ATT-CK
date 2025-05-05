import os
import json
import logging
import yaml
import pandas as pd
import pickle
from datetime import datetime
from sqlalchemy import create_engine, Table, MetaData
from sqlalchemy.exc import SQLAlchemyError
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

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

def train_model(threat_objects, model_type='naive_bayes'):
    """
    Train an ML model using the threat descriptions and their corresponding MITRE ATT&CK technique IDs.
    
    Args:
        threat_objects: List of threat objects with descriptions and technique IDs
        model_type: Type of model to train ('naive_bayes' or 'logistic_regression')
    
    Returns:
        Trained model and vectorizer
    """
    logging.info(f"Training {model_type} model...")
    
    # Check if there are any threat objects
    if not threat_objects:
        logging.warning("No threat objects provided for training. Using default model.")
        # Create a simple default model that always returns 'T1059' (Command and Scripting Interpreter)
        class DefaultModel:
            def predict(self, X):
                return ["T1059"] * X.shape[0]
        
        # Create a simple vectorizer that accepts any text
        class DefaultVectorizer:
            def transform(self, texts):
                from scipy.sparse import csr_matrix
                import numpy as np
                return csr_matrix(np.ones((len(texts), 1)))
        
        return DefaultModel(), DefaultVectorizer()
    
    # Extract descriptions and labels
    descriptions = [obj['description'] for obj in threat_objects if 'description' in obj]
    
    # Check if there are any descriptions
    if not descriptions:
        logging.warning("No descriptions found in threat objects. Using default model.")
        class DefaultModel:
            def predict(self, X):
                return ["T1059"] * X.shape[0]
        
        class DefaultVectorizer:
            def transform(self, texts):
                from scipy.sparse import csr_matrix
                import numpy as np
                return csr_matrix(np.ones((len(texts), 1)))
        
        return DefaultModel(), DefaultVectorizer()
    
    # Extract MITRE ATT&CK IDs from external references
    labels = []
    for obj in threat_objects:
        if 'external_references' in obj:
            for ref in obj['external_references']:
                if ref.get('source_name') == 'mitre-attack':
                    labels.append(ref.get('external_id'))
                    break
            else:
                # If no MITRE ATT&CK ID found, use the object ID
                labels.append(obj.get('id', 'unknown'))
        else:
            # If no external references, use the object ID
            labels.append(obj.get('id', 'unknown'))

    # Ensure descriptions and labels are of equal length
    if len(descriptions) != len(labels):
        min_length = min(len(descriptions), len(labels))
        descriptions = descriptions[:min_length]
        labels = labels[:min_length]
    
    # Check if we have enough data to train
    if len(descriptions) < 2:
        logging.warning("Not enough data to train model. Using default model.")
        class DefaultModel:
            def predict(self, X):
                return [labels[0]] * X.shape[0] if labels else ["T1059"] * X.shape[0]
        
        class DefaultVectorizer:
            def transform(self, texts):
                from scipy.sparse import csr_matrix
                import numpy as np
                return csr_matrix(np.ones((len(texts), 1)))
        
        return DefaultModel(), DefaultVectorizer()

    # Create vectorizer
    vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2))
    
    # Create model based on type
    if model_type == 'logistic_regression':
        model = LogisticRegression(max_iter=1000)
    else:  # Default to Naive Bayes
        model = MultinomialNB()
    
    try:
        # Create pipeline and train
        X = vectorizer.fit_transform(descriptions)
        model.fit(X, labels)
        
        logging.info(f"Model trained successfully with {len(descriptions)} samples")
        return model, vectorizer
    except Exception as e:
        logging.error(f"Error training model: {str(e)}. Using default model.")
        class DefaultModel:
            def predict(self, X):
                return [labels[0]] * X.shape[0] if labels else ["T1059"] * X.shape[0]
        
        class DefaultVectorizer:
            def transform(self, texts):
                from scipy.sparse import csr_matrix
                import numpy as np
                return csr_matrix(np.ones((len(texts), 1)))
        
        return DefaultModel(), DefaultVectorizer()

def save_model(model, vectorizer, model_path, vectorizer_path):
    """
    Save the trained model and vectorizer to disk.
    
    Args:
        model: Trained model
        vectorizer: TF-IDF vectorizer
        model_path: Path to save the model
        vectorizer_path: Path to save the vectorizer
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save model and vectorizer
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(vectorizer, f)
        
        logging.info(f"Model saved to {model_path} and vectorizer saved to {vectorizer_path}")
    except Exception as e:
        logging.error(f"Error saving model: {str(e)}")

def load_model(model_path, vectorizer_path):
    """
    Load the trained model and vectorizer from disk.
    
    Args:
        model_path: Path to the saved model
        vectorizer_path: Path to the saved vectorizer
    
    Returns:
        Loaded model and vectorizer
    """
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        with open(vectorizer_path, 'rb') as f:
            vectorizer = pickle.load(f)
        
        logging.info(f"Model loaded from {model_path} and vectorizer loaded from {vectorizer_path}")
        return model, vectorizer
    except Exception as e:
        logging.error(f"Error loading model: {str(e)}")
        return None, None

def predict_technique(description, model, vectorizer):
    """
    Given a threat description, predict the corresponding MITRE ATT&CK technique.
    
    Args:
        description: Threat description
        model: Trained model
        vectorizer: TF-IDF vectorizer
    
    Returns:
        Predicted MITRE ATT&CK technique ID
    """
    try:
        X = vectorizer.transform([description])
        return model.predict(X)[0]
    except Exception as e:
        logging.error(f"Error predicting technique: {str(e)}")
        return None

def map_mitre_to_stix(mitre_data):
    """
    Create a mapping from MITRE ATT&CK IDs to STIX IDs.
    
    Args:
        mitre_data: MITRE ATT&CK data
    
    Returns:
        Dictionary mapping MITRE ATT&CK IDs to STIX IDs
    """
    mitre_to_stix = {}
    for obj in mitre_data.get('objects', []):
        if obj['type'] == 'attack-pattern' and 'external_references' in obj:
            for reference in obj['external_references']:
                if reference['source_name'] == 'mitre-attack':
                    mitre_id = reference['external_id']
                    stix_id = obj['id']
                    mitre_to_stix[mitre_id] = stix_id
    return mitre_to_stix

def map_threat_data(threat_data, model, vectorizer):
    """
    Map threat data to MITRE ATT&CK techniques using the trained model.
    
    Args:
        threat_data: Threat data to map
        model: Trained model
        vectorizer: TF-IDF vectorizer
    
    Returns:
        List of mappings between threats and techniques
    """
    logging.info("Mapping threat data to MITRE ATT&CK techniques...")
    
    # Create mapping from MITRE ATT&CK IDs to STIX IDs
    mitre_to_stix = map_mitre_to_stix(threat_data)
    
    # Create mapping from STIX IDs to technique names
    stix_to_name = {}
    for obj in threat_data.get('objects', []):
        if obj['type'] == 'attack-pattern':
            stix_to_name[obj['id']] = obj.get('name', 'Unknown Technique')
    
    # Map threats to techniques
    mappings = []
    for threat in threat_data.get('objects', []):
        if 'description' in threat:
            # Predict technique ID
            external_id = predict_technique(threat['description'], model, vectorizer)
            
            if external_id:
                # Get STIX ID and technique name
                stix_id = mitre_to_stix.get(external_id)
                technique_name = stix_to_name.get(stix_id, 'Unknown Technique')
                
                # Create mapping
                mapping = {
                    'threat_id': threat['id'],
                    'external_id': external_id,
                    'technique_name': technique_name,
                    'stix_id': stix_id,
                    'description': threat.get('description', ''),
                    'source': 'MITRE ATT&CK',
                    'timestamp': datetime.now().isoformat()
                }
                
                mappings.append(mapping)
    
    logging.info(f"Mapped {len(mappings)} threats to MITRE ATT&CK techniques")
    return mappings

def save_mappings_to_file(mappings, output_file_path):
    """
    Save mappings to a JSON file.
    
    Args:
        mappings: List of mappings
        output_file_path: Path to save the mappings
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        
        # Save mappings
        with open(output_file_path, 'w') as f:
            json.dump(mappings, f, indent=4)
        
        logging.info(f"Mappings saved to {output_file_path}")
    except Exception as e:
        logging.error(f"Error saving mappings: {str(e)}")

def store_mappings_in_db(mappings, db_url):
    """
    Store mappings in the database.
    
    Args:
        mappings: List of mappings
        db_url: Database URL
    """
    try:
        engine = create_engine(db_url)
        metadata = MetaData()
        conn = engine.connect()
        
        # Reflect the existing table
        metadata.reflect(bind=engine)
        mapped_threat_data_table = Table('mapped_threat_data', metadata, autoload_with=engine)
        
        # Insert mappings
        for mapping in mappings:
            # Convert timestamp string to datetime if needed
            timestamp = mapping.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                timestamp = datetime.now()
            
            # Insert mapping
            insert_stmt = mapped_threat_data_table.insert().values(
                id=mapping.get('id', str(os.urandom(16).hex())),
                threat_id=mapping.get('threat_id', ''),
                technique_id=mapping.get('external_id', ''),
                description=mapping.get('description', ''),
                source=mapping.get('source', 'MITRE ATT&CK'),
                timestamp=timestamp
            )
            
            conn.execute(insert_stmt)
        
        logging.info(f"Stored {len(mappings)} mappings in the database")
        conn.close()
    except SQLAlchemyError as e:
        logging.error(f"Error storing mappings in database: {str(e)}")

def visualize_mappings(mappings, output_file_path='data/processed/mappings.csv'):
    """
    Visualize mappings by saving them to a CSV file.
    
    Args:
        mappings: List of mappings
        output_file_path: Path to save the CSV file
    """
    try:
        # Convert mappings to DataFrame
        df = pd.DataFrame(mappings)
        
        # Print DataFrame
        print(df)
        
        # Save to CSV
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        df.to_csv(output_file_path, index=False)
        
        logging.info(f"Mappings visualized and saved to {output_file_path}")
    except Exception as e:
        logging.error(f"Error visualizing mappings: {str(e)}")

def map_threat_data_workflow():
    """
    End-to-end workflow for mapping threat data to MITRE ATT&CK techniques.
    """
    # Define file paths
    mitre_data_path = 'data/raw/mitre_attack_data.json'
    model_path = 'models/threat_mapping_model.pkl'
    vectorizer_path = 'models/threat_mapping_vectorizer.pkl'
    mappings_path = 'data/processed/mapped_threat_data.json'
    
    # Load MITRE ATT&CK data
    try:
        with open(mitre_data_path, 'r') as f:
            mitre_data = json.load(f)
    except Exception as e:
        logging.error(f"Error loading MITRE ATT&CK data: {str(e)}")
        return
    
    # Check if model exists
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        # Load existing model
        model, vectorizer = load_model(model_path, vectorizer_path)
    else:
        # Train new model
        model, vectorizer = train_model(mitre_data.get('objects', []), model_type='logistic_regression')
        
        # Save model
        save_model(model, vectorizer, model_path, vectorizer_path)
    
    # Map threat data
    mappings = map_threat_data(mitre_data, model, vectorizer)
    
    # Save mappings
    save_mappings_to_file(mappings, mappings_path)
    
    # Visualize mappings
    visualize_mappings(mappings)
    
    # Store mappings in database
    db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['dbname']}"
    store_mappings_in_db(mappings, db_url)
    
    logging.info("Threat data mapping workflow completed")

if __name__ == "__main__":
    map_threat_data_workflow()
