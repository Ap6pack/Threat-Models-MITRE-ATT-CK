import logging
from sqlalchemy import create_engine, Table, MetaData
from sqlalchemy.exc import SQLAlchemyError
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

# Step 1: Train the Machine Learning Model
def train_model(threat_objects):
    """
    Train an ML model using the threat descriptions and their corresponding MITRE ATT&CK technique IDs.
    """
    descriptions = [obj['description'] for obj in threat_objects if 'description' in obj]
    labels = [ref['external_id'] for obj in threat_objects for ref in obj.get('external_references', []) if ref['source_name'] == 'mitre-attack']

    if len(descriptions) != len(labels):
        labels = labels[:len(descriptions)]  # Handle any mismatches in data

    # TF-IDF vectorizer and Naive Bayes classifier
    vectorizer = TfidfVectorizer()
    model = MultinomialNB()
    pipeline = make_pipeline(vectorizer, model)
    pipeline.fit(descriptions, labels)
    
    logging.info("Model trained successfully.")
    return pipeline, vectorizer

# Step 2: Predict MITRE ATT&CK Techniques
def predict_technique(description, model, vectorizer):
    """
    Given a threat description, predict the corresponding MITRE ATT&CK technique.
    """
    return model.predict([description])[0]

# Step 3: Map Threat Data to MITRE ATT&CK Techniques
def map_threat_data(threat_objects, model, vectorizer):
    """
    Use the trained model to map threat descriptions to MITRE ATT&CK techniques.
    """
    mapped_data = []
    for threat in threat_objects:
        if 'description' in threat:
            technique_id = predict_technique(threat['description'], model, vectorizer)
            mapped_data.append({
                'threat_id': threat['id'],
                'description': threat['description'],
                'technique_id': technique_id
            })
    return mapped_data

# Step 4: Store Mapped Data using SQLAlchemy
def store_mapped_data(mapped_data, db_url):
    """
    Store the mapped threat data into the PostgreSQL database using SQLAlchemy.
    """
    try:
        engine = create_engine(db_url)
        metadata = MetaData()
        conn = engine.connect()

        # Reflect the existing table
        metadata.reflect(bind=engine)
        mapped_threat_data_table = Table('mapped_threat_data', metadata, autoload_with=engine)

        # Insert the mapped data into the PostgreSQL table
        for data in mapped_data:
            insert_stmt = mapped_threat_data_table.insert().values(
                threat_id=data['threat_id'],
                description=data['description'],
                technique_id=data['technique_id']
            ).on_conflict_do_nothing(index_elements=['threat_id'])

            conn.execute(insert_stmt)

        logging.info("Mapped threat data inserted successfully.")
        conn.close()
    except SQLAlchemyError as e:
        logging.error(f"Error storing mapped data: {str(e)}")

# Step 5: Full Workflow - Train Model and Map Data
def map_threat_data_workflow(raw_data, db_url):
    """
    End-to-end workflow for mapping threat data to MITRE ATT&CK techniques.
    """
    threat_objects = raw_data.get('objects', [])
    
    # Train the model
    model, vectorizer = train_model(threat_objects)
    
    # Map the data
    mapped_data = map_threat_data(threat_objects, model, vectorizer)
    
    # Store the mapped data in the database
    store_mapped_data(mapped_data, db_url)
    
    logging.info("Threat data mapping and storage completed.")
