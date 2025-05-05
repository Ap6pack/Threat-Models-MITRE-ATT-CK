import dash
from dash import dcc, html, dash_table
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np
from sqlalchemy import create_engine
import logging
import yaml
import os
from datetime import datetime, timedelta

# Set up logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    filename='logs/dashboard.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load configuration
def load_config():
    """Load configuration from the settings file"""
    try:
        with open('config/settings.yaml', 'r') as f:
            config = yaml.safe_load(f)
        logger.info("Configuration loaded successfully")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        return {}

config = load_config()

# Database configuration
db_config = config.get('database', {
    'dbname': 'threat_intelligence',
    'user': 'postgres',
    'password': 'postgres',
    'host': 'localhost',
    'port': '5432'
})

def fetch_mapped_data():
    """
    Fetch threat data from the database with enhanced error handling.
    
    Returns:
        DataFrame containing threat data
    """
    try:
        # Create database connection
        db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['dbname']}"
        engine = create_engine(db_url)
        
        # Query from the threat_data table with more fields
        query = """
        SELECT m.id, m.threat_id, m.technique_id, m.source, m.timestamp, m.description,
               t.technique_name, t.tactic_name, t.tactic_id, t.platform
        FROM mapped_threat_data m
        LEFT JOIN mitre_attack_techniques t ON m.technique_id = t.mitre_attack_id
        """
        
        df = pd.read_sql_query(query, engine)
        logger.info(f"Fetched {len(df)} records from the database")
        
        # Debug information
        logger.info(f"Unique technique IDs: {df['technique_id'].nunique()}")
        logger.info(f"Unique technique names: {df['technique_name'].nunique()}")
        
        # Convert timestamp to datetime if needed
        if 'timestamp' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        return df
    
    except Exception as e:
        logger.error(f"Error fetching data from database: {str(e)}")
        # Return an empty DataFrame with expected columns to avoid errors
        return pd.DataFrame(columns=['id', 'threat_id', 'technique_id', 'source', 
                                     'timestamp', 'description', 'technique_name'])

# External stylesheets for better UI
external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

# Initialize Dash app with better styling
app = dash.Dash(
    __name__, 
    external_stylesheets=external_stylesheets,
    meta_tags=[{'name': 'viewport', 'content': 'width=device-width, initial-scale=1.0'}]
)
app.title = "Threat Intelligence Dashboard"

# Fetch the data
data = fetch_mapped_data()

# Create dropdown options
technique_options = [{'label': technique, 'value': technique} 
                    for technique in sorted(data['technique_name'].unique()) if pd.notna(technique)]

source_options = [{'label': source, 'value': source} 
                 for source in sorted(data['source'].unique()) if pd.notna(source)]

# Add tactic filtering if available
tactic_options = []
if 'tactic_name' in data.columns:
    tactic_options = [{'label': tactic, 'value': tactic} 
                     for tactic in sorted(data['tactic_name'].unique()) if pd.notna(tactic)]

# Add time range settings
if 'timestamp' in data.columns:
    min_date = data['timestamp'].min().date()
    max_date = data['timestamp'].max().date()
else:
    min_date = datetime.now().date() - timedelta(days=90)
    max_date = datetime.now().date()

# Layout of the dashboard with enhanced UI elements
app.layout = html.Div([
    # Header with title and info
    html.Div([
        html.H1("MITRE ATT&CK Threat Mapping Dashboard", className="app-header"),
        html.P("Interactive visualization of mapped threat intelligence data to MITRE ATT&CK framework"),
        html.Div([
            html.Span("Unique Techniques: "),
            html.Span(f"{data['technique_id'].nunique()}", style={"font-weight": "bold"})
        ], className="stats"),
        html.Hr()
    ], className="header"),
    
    # Main content with filters and visualizations
    html.Div([
        # Left panel - Filters
        html.Div([
            html.H3("Filters", style={"text-align": "center"}),
            
            # Technique filter
            html.Div([
                html.Label("Technique"),
                dcc.Dropdown(
                    id='technique-dropdown',
                    options=technique_options,
                    value=None,
                    placeholder="Select a technique",
                    clearable=True
                ),
            ], className="filter-item"),
            
            # Source filter
            html.Div([
                html.Label("Source"),
                dcc.Dropdown(
                    id='source-dropdown',
                    options=source_options,
                    value=None,
                    placeholder="Select a source",
                    clearable=True
                ),
            ], className="filter-item"),
            
            # Tactic filter
            html.Div([
                html.Label("Tactic"),
                dcc.Dropdown(
                    id='tactic-dropdown',
                    options=tactic_options,
                    value=None,
                    placeholder="Select a tactic",
                    clearable=True
                ),
            ], className="filter-item"),
            
            # Date range filter
            html.Div([
                html.Label("Date Range"),
                dcc.DatePickerRange(
                    id='date-range',
                    min_date_allowed=min_date,
                    max_date_allowed=max_date,
                    start_date=min_date,
                    end_date=max_date,
                    display_format='YYYY-MM-DD'
                ),
            ], className="filter-item"),
            
            # Apply filters button
            html.Button(
                'Apply Filters',
                id='apply-filters',
                className="button-primary",
                style={"width": "100%", "margin-top": "20px"}
            ),
            
            # Reset filters button
            html.Button(
                'Reset Filters',
                id='reset-filters',
                style={"width": "100%", "margin-top": "10px"}
            ),
            
            # Advanced options section
            html.Div([
                html.H4("Advanced Options", style={"margin-top": "30px", "text-align": "center"}),
                
                # Chart type selector
                html.Div([
                    html.Label("Chart Type"),
                    dcc.RadioItems(
                        id='chart-type',
                        options=[
                            {'label': 'Bar Chart', 'value': 'bar'},
                            {'label': 'Treemap', 'value': 'treemap'},
                            {'label': 'Pie Chart', 'value': 'pie'}
                        ],
                        value='bar',
                        labelStyle={'display': 'block', 'margin': '5px 0'}
                    )
                ], className="filter-item"),
                
                # Color scheme selector
                html.Div([
                    html.Label("Color Scheme"),
                    dcc.Dropdown(
                        id='color-scheme',
                        options=[
                            {'label': 'Viridis', 'value': 'viridis'},
                            {'label': 'Plasma', 'value': 'plasma'},
                            {'label': 'Inferno', 'value': 'inferno'},
                            {'label': 'Cividis', 'value': 'cividis'},
                            {'label': 'Blues', 'value': 'blues'}
                        ],
                        value='viridis'
                    )
                ], className="filter-item"),
            ], id="advanced-options"),
            
            # Export options
            html.Div([
                html.H4("Export", style={"margin-top": "30px", "text-align": "center"}),
                html.Button("Export as PNG", id="export-png", className="export-button"),
                html.Button("Export as CSV", id="export-csv", className="export-button"),
                dcc.Download(id="download-dataframe-csv"),
            ], className="export-section")
            
        ], className="three columns", id="filter-panel"),
        
        # Right panel - Visualizations
        html.Div([
            # Tabs for different visualizations
            dcc.Tabs([
                # Tab 1: Main Graph
                dcc.Tab(label="Technique Analysis", children=[
                    html.Div([
                        # Title with dynamic update based on filters
                        html.H3(id="main-graph-title", children="Mapped Threat Techniques"),
                        
                        # Main visualization
                        dcc.Graph(
                            id='mapped-techniques-graph',
                            style={"height": "500px"},
                            config={
                                'displayModeBar': True,
                                'modeBarButtonsToRemove': ['select2d', 'lasso2d'],
                                'toImageButtonOptions': {
                                    'format': 'png',
                                    'filename': 'threat_visualization',
                                    'height': 500,
                                    'width': 700,
                                    'scale': 2
                                }
                            }
                        ),
                    ], className="graph-container")
                ]),
                
                # Tab 2: Timeline Analysis
                dcc.Tab(label="Timeline Analysis", children=[
                    html.Div([
                        html.H3("Threats Over Time"),
                        dcc.Graph(
                            id='time-series-graph',
                            style={"height": "500px"}
                        ),
                    ], className="graph-container")
                ]),
                
                # Tab 3: Relationship Analysis
                dcc.Tab(label="Relationship Analysis", children=[
                    html.Div([
                        html.H3("Technique-Tactic Relationships"),
                        dcc.Graph(
                            id='relationship-graph',
                            style={"height": "500px"}
                        ),
                    ], className="graph-container")
                ]),
                
                # Tab 4: Data Table
                dcc.Tab(label="Data Table", children=[
                    html.Div([
                        html.H3("Threat Data"),
                        html.P("Showing detailed information for the selected filters"),
                        dash_table.DataTable(
                            id='data-table',
                            columns=[
                                {"name": "Technique", "id": "technique_name"},
                                {"name": "Tactic", "id": "tactic_name"},
                                {"name": "Source", "id": "source"},
                                {"name": "Date", "id": "timestamp_str"},
                                {"name": "Description", "id": "description"}
                            ],
                            data=[],
                            filter_action="native",
                            sort_action="native",
                            sort_mode="multi",
                            page_action="native",
                            page_size=10,
                            style_table={'overflowX': 'auto'},
                            style_cell={
                                'overflow': 'hidden',
                                'textOverflow': 'ellipsis',
                                'maxWidth': 0,
                            },
                            style_data_conditional=[
                                {
                                    'if': {'row_index': 'odd'},
                                    'backgroundColor': 'rgb(248, 248, 248)'
                                }
                            ],
                            style_header={
                                'backgroundColor': 'rgb(230, 230, 230)',
                                'fontWeight': 'bold'
                            }
                        ),
                    ], className="table-container")
                ]),
            ], id="visualization-tabs")
        ], className="nine columns", id="visualization-panel"),
    ], className="row", id="main-content"),
    
    # Detail panel (hidden by default, shown when a technique is selected)
    html.Div([
        html.H3("Technique Details"),
        html.Div(id='technique-details', className="details-content")
    ], id="detail-panel", style={"display": "none"}),
    
    # Footer
    html.Div([
        html.Hr(),
        html.P("Threat Models and MITRE ATT&CK Mapping Tool © 2025", style={"text-align": "center"})
    ], className="footer")
], className="app-container")

# Callback to update the main graph based on selected filters
@app.callback(
    [Output('mapped-techniques-graph', 'figure'),
     Output('main-graph-title', 'children')],
    [Input('apply-filters', 'n_clicks')],
    [dash.dependencies.State('technique-dropdown', 'value'),
     dash.dependencies.State('source-dropdown', 'value'),
     dash.dependencies.State('tactic-dropdown', 'value'),
     dash.dependencies.State('date-range', 'start_date'),
     dash.dependencies.State('date-range', 'end_date'),
     dash.dependencies.State('chart-type', 'value'),
     dash.dependencies.State('color-scheme', 'value')]
)
def update_graph(n_clicks, selected_technique, selected_source, selected_tactic, 
                start_date, end_date, chart_type, color_scheme):
    # Filter data based on selections
    filtered_data = filter_data(data, selected_technique, selected_source, 
                               selected_tactic, start_date, end_date)
    
    # Update graph title based on filters
    title_parts = ["Mapped Threat Techniques"]
    if selected_technique:
        title_parts.append(f"for {selected_technique}")
    if selected_source:
        title_parts.append(f"from {selected_source}")
    if selected_tactic:
        title_parts.append(f"in {selected_tactic} Tactic")
    
    graph_title = " ".join(title_parts)
    
    # Create different chart types based on selection
    if chart_type == 'bar':
        # Count occurrences of each technique
        technique_counts = filtered_data['technique_name'].value_counts().reset_index()
        technique_counts.columns = ['technique_name', 'count']
        
        # Sort by count (descending)
        technique_counts = technique_counts.sort_values('count', ascending=False)
        
        # Create bar chart
        fig = px.bar(
            technique_counts,
            x='technique_name',
            y='count',
            color='count',
            color_continuous_scale=color_scheme,
            template='plotly_white',
            labels={
                'technique_name': 'Technique',
                'count': 'Count'
            }
        )
        
        # Improve layout
        fig.update_layout(
            xaxis_title="Technique",
            yaxis_title="Count",
            xaxis={'categoryorder': 'total descending'},
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis_tickangle=-45,
            margin=dict(l=50, r=50, t=30, b=80)
        )
    
    elif chart_type == 'treemap':
        # Prepare data for treemap
        if 'tactic_name' in filtered_data.columns:
            # Group by tactic and technique for hierarchical view
            grouped = filtered_data.groupby(['tactic_name', 'technique_name']).size().reset_index(name='count')
            
            # Create treemap
            fig = px.treemap(
                grouped,
                path=['tactic_name', 'technique_name'],
                values='count',
                color='count',
                color_continuous_scale=color_scheme,
                template='plotly_white'
            )
        else:
            # Simple treemap with just techniques
            technique_counts = filtered_data['technique_name'].value_counts().reset_index()
            technique_counts.columns = ['technique_name', 'count']
            
            fig = px.treemap(
                technique_counts,
                path=['technique_name'],
                values='count',
                color='count',
                color_continuous_scale=color_scheme,
                template='plotly_white'
            )
        
        # Improve layout
        fig.update_layout(
            margin=dict(l=0, r=0, t=30, b=0),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
    
    elif chart_type == 'pie':
        # Count occurrences of each technique
        technique_counts = filtered_data['technique_name'].value_counts().reset_index()
        technique_counts.columns = ['technique_name', 'count']
        
        # Take top 10 for better visualization
        top_techniques = technique_counts.head(10)
        
        # Create pie chart
        fig = px.pie(
            top_techniques,
            names='technique_name',
            values='count',
            hole=0.4,
            color_discrete_sequence=px.colors.sequential.get(color_scheme, px.colors.sequential.Viridis),
            template='plotly_white'
        )
        
        # Improve layout
        fig.update_layout(
            margin=dict(l=20, r=20, t=30, b=20),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.2,
                xanchor="center",
                x=0.5
            )
        )
    
    return fig, graph_title

# Callback to update time series graph
@app.callback(
    Output('time-series-graph', 'figure'),
    [Input('apply-filters', 'n_clicks')],
    [dash.dependencies.State('technique-dropdown', 'value'),
     dash.dependencies.State('source-dropdown', 'value'),
     dash.dependencies.State('tactic-dropdown', 'value'),
     dash.dependencies.State('date-range', 'start_date'),
     dash.dependencies.State('date-range', 'end_date'),
     dash.dependencies.State('color-scheme', 'value')]
)
def update_time_series(n_clicks, selected_technique, selected_source, selected_tactic, 
                     start_date, end_date, color_scheme):
    # Filter data based on selections
    filtered_data = filter_data(data, selected_technique, selected_source, 
                               selected_tactic, start_date, end_date)
    
    # Check if timestamp column exists
    if 'timestamp' not in filtered_data.columns or filtered_data.empty:
        # Return empty figure with message
        fig = go.Figure()
        fig.add_annotation(
            text="No time data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20)
        )
        return fig
    
    # Ensure timestamp is datetime
    if not pd.api.types.is_datetime64_any_dtype(filtered_data['timestamp']):
        filtered_data['timestamp'] = pd.to_datetime(filtered_data['timestamp'])
    
    # Group by day and count
    daily_counts = filtered_data.groupby(filtered_data['timestamp'].dt.date).size().reset_index()
    daily_counts.columns = ['date', 'count']
    
    # Calculate 7-day moving average if enough data points
    fig = go.Figure()
    
    # Add daily counts
    fig.add_trace(go.Scatter(
        x=daily_counts['date'],
        y=daily_counts['count'],
        mode='lines+markers',
        name='Daily Threats',
        line=dict(color='#1f77b4', width=2),
        marker=dict(size=6)
    ))
    
    # Add moving average if we have enough data
    if len(daily_counts) >= 7:
        # Create rolling average
        rolling_data = daily_counts.copy()
        rolling_data['moving_avg'] = rolling_data['count'].rolling(window=7, min_periods=1).mean()
        