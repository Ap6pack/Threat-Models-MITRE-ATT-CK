import logging
import json
import os
import time
from functools import lru_cache
import pandas as pd
import dash
from dash import html
import traceback
import yaml

# Set up logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    filename='logs/error_handling.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Cache settings
CACHE_TTL = 300  # Time to live for cached data in seconds
CACHE_SIZE = 32  # Number of items to cache

# Load configuration
def load_config():
    """Load configuration from YAML file"""
    try:
        with open('config/settings.yaml', 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        return {}

# Error handling functions
def log_error(func_name, error, additional_info=None):
    """
    Log an error with detailed information
    
    Args:
        func_name: Name of the function where the error occurred
        error: The error object
        additional_info: Any additional context information
    """
    error_msg = f"Error in {func_name}: {str(error)}"
    
    if additional_info:
        error_msg += f" | Additional info: {additional_info}"
    
    logger.error(error_msg)
    logger.error(traceback.format_exc())

def create_error_message(error_type, message, suggestions=None):
    """
    Create a standardized error message for the dashboard
    
    Args:
        error_type: Type of error (e.g., 'Database Error', 'Data Format Error')
        message: Main error message
        suggestions: List of suggestions for the user
    
    Returns:
        Dash HTML component to display the error
    """
    # Default suggestions if none provided
    if not suggestions:
        suggestions = [
            "Refresh the page and try again",
            "Check your database connection",
            "Verify the data format is correct"
        ]
    
    return html.Div([
        html.H4(f"Error: {error_type}", style={'color': '#d9534f'}),
        html.P(message),
        html.H5("Suggestions:"),
        html.Ul([html.Li(suggestion) for suggestion in suggestions]),
        html.Hr(),
        html.P("If the issue persists, please check the logs or contact the administrator.",
              style={'font-style': 'italic', 'color': '#666'})
    ], className="error-message", style={
        'backgroundColor': '#f2dede',
        'border': '1px solid #ebccd1',
        'borderRadius': '4px',
        'padding': '15px',
        'marginBottom': '20px'
    })

def handle_data_loading_error(error, function_name):
    """
    Handle errors during data loading and provide appropriate feedback
    
    Args:
        error: The error that occurred
        function_name: Name of the function where the error occurred
        
    Returns:
        Tuple containing:
            - Boolean indicating success/failure
            - Error message component (if failure) or None (if success)
    """
    log_error(function_name, error)
    
    # Categorize errors
    if 'connection' in str(error).lower() or 'timeout' in str(error).lower():
        return False, create_error_message(
            "Database Connection Error",
            "Unable to connect to the database. The server might be down or the connection parameters incorrect.",
            [
                "Check that the database server is running",
                "Verify database connection parameters in config/settings.yaml",
                "Check network connectivity to the database server",
                "Try loading data from file instead"
            ]
        )
    elif 'file not found' in str(error).lower() or 'no such file' in str(error).lower():
        return False, create_error_message(
            "File Not Found Error",
            "The specified data file could not be found.",
            [
                "Verify file path in config/settings.yaml",
                "Check if the file exists in the specified location",
                "Try running data ingestion process first"
            ]
        )
    elif 'json' in str(error).lower() or 'parse' in str(error).lower():
        return False, create_error_message(
            "Data Format Error",
            "The data file is corrupted or in an incorrect format.",
            [
                "Check the data file format",
                "Try regenerating the data file",
                "Run the data ingestion process again"
            ]
        )
    else:
        return False, create_error_message(
            "Unknown Error",
            f"An unexpected error occurred: {str(error)}",
            [
                "Check the logs for more details",
                "Try restarting the application",
                "Contact the administrator"
            ]
        )

# Performance optimization functions
@lru_cache(maxsize=CACHE_SIZE)
def cached_data_fetch(source='db', file_path=None, cache_key=None):
    """
    Fetch data with caching to improve performance
    
    Args:
        source: Source of data ('db' or 'file')
        file_path: Path to the file (if source is 'file')
        cache_key: Optional key to differentiate cache entries
        
    Returns:
        DataFrame containing the data
    """
    # Add timestamp to cache key to invalidate cache after TTL
    timestamp = int(time.time() / CACHE_TTL)
    cache_key = f"{source}_{file_path}_{cache_key}_{timestamp}"
    
    logger.info(f"Fetching data with cache key: {cache_key}")
    
    try:
        # Import dynamically to avoid circular imports
        from scripts.visualization.consolidated_dashboard import fetch_data_from_db, fetch_data_from_file
        
        if source == 'db':
            return fetch_data_from_db()
        else:
            return fetch_data_from_file(file_path)
    except Exception as e:
        log_error("cached_data_fetch", e)
        return pd.DataFrame()

def optimize_dataframe(df):
    """
    Optimize a DataFrame to reduce memory usage
    
    Args:
        df: DataFrame to optimize
        
    Returns:
        Optimized DataFrame
    """
    start_mem = df.memory_usage().sum() / 1024**2
    logger.info(f"DataFrame memory usage before optimization: {start_mem:.2f} MB")
    
    # Optimize numeric columns
    for col in df.select_dtypes(include=['int']):
        c_min = df[col].min()
        c_max = df[col].max()
        
        # Convert to smallest possible int type
        if c_min > -128 and c_max < 127:
            df[col] = df[col].astype('int8')
        elif c_min > -32768 and c_max < 32767:
            df[col] = df[col].astype('int16')
        elif c_min > -2147483648 and c_max < 2147483647:
            df[col] = df[col].astype('int32')
    
    # Optimize float columns
    for col in df.select_dtypes(include=['float']):
        df[col] = df[col].astype('float32')
    
    # Optimize object columns (strings)
    for col in df.select_dtypes(include=['object']):
        if len(df[col].unique()) / len(df) < 0.5:  # If less than 50% unique values
            df[col] = df[col].astype('category')
    
    end_mem = df.memory_usage().sum() / 1024**2
    logger.info(f"DataFrame memory usage after optimization: {end_mem:.2f} MB")
    logger.info(f"Memory reduced by {100 * (start_mem - end_mem) / start_mem:.2f}%")
    
    return df

def lazy_load_visualization(app, component_id, layout_function, data_function):
    """
    Implement lazy loading for visualizations to improve initial load time
    
    Args:
        app: Dash app instance
        component_id: ID of the component to lazy load
        layout_function: Function that returns the component layout
        data_function: Function that fetches the data for the component
        
    Returns:
        None
    """
    # Create loading layout
    loading_layout = html.Div([
        html.Div(
            className="loading-spinner",
            children=[
                html.Div(className="spinner")
            ]
        ),
        html.P("Loading visualization...", className="loading-text")
    ], className="loading-container")
    
    # Register callback to load data only when tab is selected
    @app.callback(
        dash.dependencies.Output(component_id, 'children'),
        [dash.dependencies.Input('dashboard-tabs', 'active_tab')]
    )
    def update_component(active_tab):
        # Only load data when this tab is active
        if active_tab == component_id.split('-')[0]:
            try:
                start_time = time.time()
                # Get data
                data = data_function()
                
                # Check if data is valid
                if data is None or (isinstance(data, pd.DataFrame) and data.empty):
                    return create_error_message(
                        "No Data Available",
                        "No data is available for this visualization.",
                        [
                            "Check that data has been ingested",
                            "Verify that the database contains mapped threat data",
                            "Apply less restrictive filters"
                        ]
                    )
                
                # Create layout with data
                result = layout_function(data)
                
                # Log performance
                end_time = time.time()
                logger.info(f"Visualization {component_id} loaded in {end_time - start_time:.2f} seconds")
                
                return result
            except Exception as e:
                log_error(f"lazy_load_{component_id}", e)
                return create_error_message(
                    "Visualization Error",
                    f"An error occurred while loading this visualization: {str(e)}",
                    [
                        "Refresh the page and try again",
                        "Check the logs for more details"
                    ]
                )
        else:
            # Return loading layout when tab is not active
            return loading_layout

# Graceful fallbacks
def get_fallback_data():
    """
    Get fallback sample data when no actual data is available
    
    Returns:
        DataFrame with sample data
    """
    logger.info("Using fallback sample data")
    
    # Create sample data with MITRE ATT&CK techniques
    techniques = [
        "Data Obfuscation", "System Information Discovery", "Account Discovery",
        "Credential Dumping", "Process Injection", "Registry Run Keys",
        "PowerShell", "Command-Line Interface", "File Deletion"
    ]
    
    tactics = [
        "Defense Evasion", "Discovery", "Discovery", 
        "Credential Access", "Defense Evasion", "Persistence",
        "Execution", "Execution", "Defense Evasion"
    ]
    
    sources = ["MITRE ATT&CK", "AlienVault OTX", "VirusTotal"]
    
    # Create sample DataFrame
    import numpy as np
    from datetime import datetime, timedelta
    
    # Generate 50 sample records
    n_samples = 50
    
    sample_data = pd.DataFrame({
        'id': range(1, n_samples + 1),
        'threat_id': [f'T{i}' for i in range(1, n_samples + 1)],
        'technique_id': [f'T100{i%9 + 1}' for i in range(n_samples)],
        'technique_name': [techniques[i % len(techniques)] for i in range(n_samples)],
        'tactic_name': [tactics[i % len(tactics)] for i in range(n_samples)],
        'source': [sources[i % len(sources)] for i in range(n_samples)],
        'timestamp': [datetime.now() - timedelta(days=i % 30) for i in range(n_samples)],
        'description': [f'Sample threat description for {techniques[i % len(techniques)]}' for i in range(n_samples)]
    })
    
    return sample_data

def create_fallback_message(component, error_type, message):
    """
    Create a fallback message with sample visualization when actual data can't be loaded
    
    Args:
        component: The component that failed to load
        error_type: Type of error
        message: Error message
        
    Returns:
        Dash HTML component with error message and sample visualization
    """
    sample_data = get_fallback_data()
    
    return html.Div([
        # Error message
        html.Div([
            html.H4(f"Error: {error_type}", style={'color': '#d9534f'}),
            html.P(message),
            html.P("A sample visualization is shown below using mock data."),
            html.Hr()
        ], style={
            'backgroundColor': '#f2dede',
            'border': '1px solid #ebccd1',
            'borderRadius': '4px',
            'padding': '15px',
            'marginBottom': '20px'
        }),
        
        # Sample visualization
        html.Div([
            html.H5("Sample Visualization (using mock data)"),
            component(sample_data)
        ], style={
            'backgroundColor': '#fcf8e3',
            'border': '1px solid #faebcc',
            'borderRadius': '4px',
            'padding': '15px'
        })
    ])

# Export functions for use in dashboards
__all__ = [
    'log_error',
    'create_error_message',
    'handle_data_loading_error',
    'cached_data_fetch',
    'optimize_dataframe',
    'lazy_load_visualization',
    'get_fallback_data',
    'create_fallback_message'
]

    