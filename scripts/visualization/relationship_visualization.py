import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import logging
from sqlalchemy import create_engine
import yaml
import os
import json
from datetime import datetime

# Set up logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    filename='logs/relationship_visualization.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_config():
    """Load configuration from YAML file"""
    try:
        with open('config/settings.yaml', 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        return {}

def fetch_data_from_db():
    """Fetch data from the database"""
    config = load_config()
    db_config = config.get('database', {
        'dbname': 'threat_intelligence',
        'user': 'postgres',
        'password': 'postgres',
        'host': 'localhost',
        'port': '5432'
    })
    
    try:
        # Create database connection
        db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['dbname']}"
        engine = create_engine(db_url)
        
        # Query with joined data for relationships
        query = """
        SELECT 
            m.id, 
            m.threat_id, 
            m.technique_id, 
            m.source, 
            m.timestamp,
            t.technique_name,
            t.tactic_name,
            t.tactic_id,
            t.platform,
            t.data_sources
        FROM mapped_threat_data m
        LEFT JOIN mitre_attack_techniques t ON m.technique_id = t.mitre_attack_id
        """
        
        df = pd.read_sql_query(query, engine)
        logger.info(f"Fetched {len(df)} records from the database")
        return df
    
    except Exception as e:
        logger.error(f"Error fetching data from database: {str(e)}")
        return pd.DataFrame()

def fetch_data_from_file(file_path='data/processed/mapped_threat_data.json'):
    """Fetch data from a JSON file if database is unavailable"""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        df = pd.DataFrame(data)
        logger.info(f"Fetched {len(df)} records from file {file_path}")
        return df
    
    except Exception as e:
        logger.error(f"Error fetching data from file: {str(e)}")
        return pd.DataFrame()

def create_technique_tactic_heatmap(data, output_file='reports/technique_tactic_heatmap.html'):
    """
    Create a heatmap visualization showing the relationship between techniques and tactics
    
    Args:
        data: DataFrame containing threat data
        output_file: Path to save the output HTML file
    
    Returns:
        Plotly figure object
    """
    try:
        # Check if necessary columns exist
        if 'technique_name' not in data.columns or 'tactic_name' not in data.columns:
            logger.error("Required columns 'technique_name' or 'tactic_name' missing")
            return None
        
        # Filter out rows with missing values
        filtered_data = data.dropna(subset=['technique_name', 'tactic_name'])
        
        if filtered_data.empty:
            logger.warning("No valid data for technique-tactic relationships")
            return None
        
        # Group by technique and tactic, count occurrences
        relationship_counts = filtered_data.groupby(['technique_name', 'tactic_name']).size().reset_index(name='count')
        
        # Pivot the data to create a matrix suitable for heatmap
        pivot_table = relationship_counts.pivot_table(
            values='count',
            index='tactic_name',
            columns='technique_name',
            fill_value=0
        )
        
        # Create heatmap
        fig = px.imshow(
            pivot_table,
            labels=dict(x="Technique", y="Tactic", color="Count"),
            x=pivot_table.columns,
            y=pivot_table.index,
            color_continuous_scale="Viridis"
        )
        
        # Customize layout
        fig.update_layout(
            title="Technique-Tactic Relationship Heatmap",
            xaxis_title="Technique",
            yaxis_title="Tactic",
            xaxis={'tickangle': -45},
            height=800,
            width=1200,
            margin=dict(l=100, r=50, t=100, b=150)
        )
        
        # Save to HTML file if output_file is provided
        if output_file:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Save figure to HTML
            fig.write_html(output_file)
            logger.info(f"Technique-tactic heatmap saved to {output_file}")
        
        return fig
    
    except Exception as e:
        logger.error(f"Error creating technique-tactic heatmap: {str(e)}")
        return None

def create_technique_relationship_network(data, output_file='reports/technique_relationship_network.html'):
    """
    Create a network visualization showing relationships between techniques based on common tactics
    
    Args:
        data: DataFrame containing threat data
        output_file: Path to save the output HTML file
    
    Returns:
        Plotly figure object
    """
    try:
        # Check if necessary columns exist
        if 'technique_name' not in data.columns or 'tactic_name' not in data.columns:
            logger.error("Required columns missing")
            return None
        
        # Filter out rows with missing values
        filtered_data = data.dropna(subset=['technique_name', 'tactic_name'])
        
        if filtered_data.empty:
            logger.warning("No valid data for technique relationships")
            return None
        
        # Get unique techniques and tactics
        unique_techniques = filtered_data['technique_name'].unique()
        
        # Create a matrix to store relationship strengths
        # (techniques that share tactics are related)
        num_techniques = len(unique_techniques)
        relationship_matrix = np.zeros((num_techniques, num_techniques))
        
        # Map technique names to indices
        technique_to_index = {tech: i for i, tech in enumerate(unique_techniques)}
        
        # For each tactic, strengthen the relationship between all techniques that share it
        for tactic in filtered_data['tactic_name'].unique():
            # Get techniques for this tactic
            tactic_techniques = filtered_data[filtered_data['tactic_name'] == tactic]['technique_name'].unique()
            
            # For each pair of techniques that share this tactic, increment their relationship strength
            for i, tech1 in enumerate(tactic_techniques):
                for tech2 in tactic_techniques[i+1:]:  # Start from i+1 to avoid self-loops and duplicate pairs
                    idx1 = technique_to_index[tech1]
                    idx2 = technique_to_index[tech2]
                    
                    # Increment relationship strength
                    relationship_matrix[idx1, idx2] += 1
                    relationship_matrix[idx2, idx1] += 1  # Symmetric
        
        # Create edges for the network
        edges = []
        for i in range(num_techniques):
            for j in range(i+1, num_techniques):  # Start from i+1 to avoid self-loops and duplicate edges
                if relationship_matrix[i, j] > 0:
                    edges.append((i, j, relationship_matrix[i, j]))
        
        # Create node positions using a basic layout algorithm
        # This is a simple circular layout, but more complex layouts could be used
        node_positions = {}
        angle_step = 2 * np.pi / num_techniques
        radius = 1
        
        for i, technique in enumerate(unique_techniques):
            angle = i * angle_step
            x = radius * np.cos(angle)
            y = radius * np.sin(angle)
            node_positions[i] = (x, y)
        
        # Create the network visualization
        fig = go.Figure()
        
        # Add edges (links)
        for i, j, weight in edges:
            # Only show stronger relationships to avoid clutter
            if weight > 1:  # Adjust this threshold as needed
                fig.add_trace(go.Scatter(
                    x=[node_positions[i][0], node_positions[j][0]],
                    y=[node_positions[i][1], node_positions[j][1]],
                    mode='lines',
                    line=dict(width=weight, color='rgba(100,100,100,0.2)'),
                    hoverinfo='none'
                ))
        
        # Add nodes
        node_x = [pos[0] for pos in node_positions.values()]
        node_y = [pos[1] for pos in node_positions.values()]
        
        # Get technique count for node size
        technique_counts = filtered_data['technique_name'].value_counts()
        node_sizes = [technique_counts.get(tech, 1) * 10 for tech in unique_techniques]
        
        # Add node trace
        fig.add_trace(go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            marker=dict(
                size=node_sizes,
                color=list(range(len(unique_techniques))),
                colorscale='Viridis',
                line=dict(width=2, color='white')
            ),
            text=unique_techniques,
            textposition="top center",
            hoverinfo='text',
            textfont=dict(size=10)
        ))
        
        # Customize layout
        fig.update_layout(
            title="Technique Relationship Network",
            showlegend=False,
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=800,
            width=1000,
            margin=dict(l=50, r=50, t=100, b=50)
        )
        
        # Save to HTML file if output_file is provided
        if output_file:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Save figure to HTML
            fig.write_html(output_file)
            logger.info(f"Technique relationship network saved to {output_file}")
        
        return fig
    
    except Exception as e:
        logger.error(f"Error creating technique relationship network: {str(e)}")
        return None

def create_source_technique_sankey(data, output_file='reports/source_technique_sankey.html'):
    """
    Create a Sankey diagram showing the flow from sources to techniques
    
    Args:
        data: DataFrame containing threat data
        output_file: Path to save the output HTML file
    
    Returns:
        Plotly figure object
    """
    try:
        # Check if necessary columns exist
        if 'technique_name' not in data.columns or 'source' not in data.columns:
            logger.error("Required columns missing")
            return None
        
        # Filter out rows with missing values
        filtered_data = data.dropna(subset=['technique_name', 'source'])
        
        if filtered_data.empty:
            logger.warning("No valid data for Sankey diagram")
            return None
        
        # Get unique sources and techniques
        unique_sources = filtered_data['source'].unique()
        unique_techniques = filtered_data['technique_name'].unique()
        
        # Create node labels (sources + techniques)
        labels = list(unique_sources) + list(unique_techniques)
        
        # Create a mapping from node names to indices
        node_indices = {name: i for i, name in enumerate(labels)}
        
        # Count source-technique pairs
        source_technique_counts = filtered_data.groupby(['source', 'technique_name']).size().reset_index(name='count')
        
        # Create source, target, and value lists for Sankey diagram
        sources = []
        targets = []
        values = []
        
        for _, row in source_technique_counts.iterrows():
            source_idx = node_indices[row['source']]
            target_idx = node_indices[row['technique_name']]
            
            sources.append(source_idx)
            targets.append(target_idx)
            values.append(row['count'])
        
        # Create Sankey diagram
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=labels,
                color="blue"
            ),
            link=dict(
                source=sources,
                target=targets,
                value=values,
                color="rgba(100,100,100,0.2)"
            )
        )])
        
        # Customize layout
        fig.update_layout(
            title_text="Flow from Sources to Techniques",
            font_size=10,
            height=800,
            width=1200,
            margin=dict(l=50, r=50, t=100, b=50)
        )
        
        # Save to HTML file if output_file is provided
        if output_file:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Save figure to HTML
            fig.write_html(output_file)
            logger.info(f"Source-technique Sankey diagram saved to {output_file}")
        
        return fig
    
    except Exception as e:
        logger.error(f"Error creating source-technique Sankey diagram: {str(e)}")
        return None

def create_all_relationship_visualizations():
    """Create all relationship visualizations"""
    # Fetch data
    data = fetch_data_from_db()
    
    if data.empty:
        # Try to fetch from file if database is empty
        data = fetch_data_from_file()
    
    if data.empty:
        logger.error("No data available for visualization")
        return False
    
    # Create visualizations
    heatmap_fig = create_technique_tactic_heatmap(data)
    network_fig = create_technique_relationship_network(data)
    sankey_fig = create_source_technique_sankey(data)
    
    if heatmap_fig and network_fig and sankey_fig:
        logger.info("All relationship visualizations created successfully")
        return True
    else:
        logger.warning("Some relationship visualizations could not be created")
        return False

if __name__ == "__main__":
    # Create all relationship visualizations
    create_all_relationship_visualizations()
