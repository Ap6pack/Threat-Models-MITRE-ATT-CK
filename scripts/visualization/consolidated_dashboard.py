import os
import json
import logging
import yaml
import pandas as pd
import folium
from folium.plugins import MarkerCluster, HeatMap
import matplotlib.pyplot as plt
import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output, State
import plotly.express as px
import plotly.graph_objects as go
from sqlalchemy import create_engine
from datetime import datetime, timedelta

# Load configuration
def load_config():
    try:
        with open('config/settings.yaml', 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logging.error(f"Error loading configuration: {str(e)}")
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

# Visualization configuration
viz_config = config.get('visualization', {
    'default_map_zoom': 2,
    'default_map_center': [20, 0],
    'max_techniques_in_chart': 15,
    'color_scheme': 'viridis'
})

# Set up logging
os.makedirs('logs', exist_ok=True)
logging.basicConfig(filename='logs/app.log', level=logging.INFO,
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fetch_data_from_db():
    """
    Fetch threat data from the database with enhanced error handling and logging.
    
    Returns:
        DataFrame containing threat data
    """
    try:
        # Create database connection
        db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['dbname']}"
        engine = create_engine(db_url)
        
        # Query mapped threat data with additional context
        query = """
        SELECT 
            m.id, 
            m.threat_id, 
            m.technique_id, 
            m.description, 
            m.source, 
            m.timestamp,
            t.technique_name
        FROM mapped_threat_data m
        LEFT JOIN mitre_attack_techniques t ON m.technique_id = t.mitre_attack_id
        """
        
        df = pd.read_sql_query(query, engine)
        logger.info(f"Fetched {len(df)} records from the database")
        
        # Convert timestamp to datetime if needed
        if 'timestamp' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        return df
    
    except Exception as e:
        logger.error(f"Error fetching data from database: {str(e)}")
        return pd.DataFrame()

def fetch_data_from_file(file_path):
    """
    Fetch threat data from a JSON file with enhanced error handling.
    
    Args:
        file_path: Path to the JSON file
    
    Returns:
        DataFrame containing threat data
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        df = pd.DataFrame(data)
        logger.info(f"Fetched {len(df)} records from {file_path}")
        
        # Convert timestamp to datetime if needed
        if 'timestamp' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        return df
    
    except Exception as e:
        logger.error(f"Error fetching data from file: {str(e)}")
        return pd.DataFrame()

def create_interactive_map(data, output_file_path='reports/threat_map.html'):
    """
    Create an enhanced interactive map of threat data using folium.
    
    Args:
        data: DataFrame containing threat data with location information
        output_file_path: Path to save the HTML map
    """
    try:
        # Check if data has location information
        if 'latitude' not in data.columns or 'longitude' not in data.columns:
            logger.warning("Data does not have location information, skipping map creation")
            return
        
        # Initialize the map centered around the average coordinates or default
        map_center = viz_config.get('default_map_center', [20, 0])
        map_zoom = viz_config.get('default_map_zoom', 2)
        m = folium.Map(location=map_center, zoom_start=map_zoom, tiles="OpenStreetMap")
        
        # Add layer control for different tile options
        folium.TileLayer('CartoDB positron', name='Light Map').add_to(m)
        folium.TileLayer('CartoDB dark_matter', name='Dark Map').add_to(m)
        
        # Add marker cluster with custom options
        marker_cluster = MarkerCluster(
            name="Threat Markers",
            overlay=True,
            control=True,
            icon_create_function=None
        ).add_to(m)
        
        # Create heat map data
        heat_data = []
        
        # Add markers for each threat
        for _, row in data.iterrows():
            if pd.notna(row['latitude']) and pd.notna(row['longitude']):
                # Add data for heat map
                heat_data.append([row['latitude'], row['longitude'], 1])
                
                # Determine marker color based on source
                source_colors = {
                    'MITRE ATT&CK': 'red',
                    'AlienVault OTX': 'orange',
                    'VirusTotal': 'purple',
                    'Custom': 'blue'
                }
                
                source = row.get('source', 'Custom')
                color = source_colors.get(source, 'blue')
                
                # Enhanced popup content with more threat details
                popup_content = f"""
                <div style="width: 300px;">
                    <h4>{row.get('technique_name', 'Unknown Technique')}</h4>
                    <b>Threat ID:</b> {row.get('threat_id', 'N/A')}<br>
                    <b>Technique ID:</b> {row.get('technique_id', 'N/A')}<br>
                    <b>Source:</b> {row.get('source', 'N/A')}<br>
                    <b>Date:</b> {row.get('timestamp', 'N/A')}<br>
                    <hr>
                    <p><b>Description:</b><br> {row.get('description', 'N/A')[:200]}...</p>
                </div>
                """
                
                # Add marker with custom icon based on source
                folium.Marker(
                    location=[row['latitude'], row['longitude']],
                    popup=folium.Popup(popup_content, max_width=300),
                    icon=folium.Icon(color=color, icon='info-sign')
                ).add_to(marker_cluster)
        
        # Add heat map as another layer
        HeatMap(heat_data, name="Threat Heatmap").add_to(m)
        
        # Add layer control
        folium.LayerControl().add_to(m)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        
        # Save the map
        m.save(output_file_path)
        logger.info(f"Enhanced interactive map saved to {output_file_path}")
    
    except Exception as e:
        logger.error(f"Error creating interactive map: {str(e)}")

def plot_threat_types(data, output_file_path='reports/threat_types_distribution.png'):
    """
    Create an enhanced bar chart of threat types distribution.
    
    Args:
        data: DataFrame containing threat data
        output_file_path: Path to save the chart
    """
    try:
        # Check if data has technique_name column
        if 'technique_name' not in data.columns:
            logger.warning("Data does not have technique_name column, skipping threat types plot")
            return
        
        # Count occurrences of each technique
        max_techniques = viz_config.get('max_techniques_in_chart', 15)
        threat_counts = data['technique_name'].value_counts().head(max_techniques)
        
        # Check if we have any data to plot
        if len(threat_counts) == 0:
            logger.warning("No threat data to plot, creating empty chart")
            plt.figure(figsize=(14, 8))
            plt.title('No Threat Data Available', fontsize=18, fontweight='bold')
            plt.xlabel('Technique', fontsize=14)
            plt.ylabel('Count', fontsize=14)
            plt.tight_layout()
            plt.savefig(output_file_path, dpi=300)
            plt.close()
            return
        
        # Create figure with enhanced styling
        plt.figure(figsize=(14, 8))
        
        # Create a colormap with the right number of colors
        colors = plt.cm.get_cmap(viz_config.get('color_scheme', 'viridis'))(
            [i/float(max(1, len(threat_counts)-1)) for i in range(len(threat_counts))]
        )
            
        ax = threat_counts.plot(
            kind='bar', 
            color=colors
        )
        
        # Enhanced styling
        plt.title('Top MITRE ATT&CK Techniques', fontsize=18, fontweight='bold')
        plt.xlabel('Technique', fontsize=14)
        plt.ylabel('Count', fontsize=14)
        plt.xticks(rotation=45, ha='right', fontsize=12)
        plt.yticks(fontsize=12)
        
        # Add count labels on top of bars
        for i, v in enumerate(threat_counts):
            ax.text(i, v + 0.3, str(v), ha='center', fontsize=10)
        
        # Add grid for better readability
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Tight layout and adjust for bar labels
        plt.tight_layout()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        
        # Save the chart with high DPI for better quality
        plt.savefig(output_file_path, dpi=300)
        logger.info(f"Enhanced threat types distribution chart saved to {output_file_path}")
        
        # Close the figure to free memory
        plt.close()
    
    except Exception as e:
        logger.error(f"Error plotting threat types: {str(e)}")

def plot_threats_over_time(data, output_file_path='reports/threats_over_time.png'):
    """
    Create an enhanced line chart of threats over time with trend analysis.
    
    Args:
        data: DataFrame containing threat data
        output_file_path: Path to save the chart
    """
    try:
        # Check if data has timestamp column
        if 'timestamp' not in data.columns:
            logger.warning("Data does not have timestamp column, skipping threats over time plot")
            return
        
        # Convert timestamp to datetime if it's not already
        if not pd.api.types.is_datetime64_any_dtype(data['timestamp']):
            data['timestamp'] = pd.to_datetime(data['timestamp'])
        
        # Group by day and count
        data.set_index('timestamp', inplace=True)
        threats_over_time = data.resample('D').size()
        
        # Calculate 7-day moving average for trend analysis
        rolling_avg = threats_over_time.rolling(window=7).mean()
        
        # Create figure with enhanced styling
        plt.figure(figsize=(14, 8))
        
        # Plot daily counts
        ax = threats_over_time.plot(
            linestyle='-', 
            marker='o', 
            markersize=4, 
            alpha=0.7,
            color='#1f77b4',
            label='Daily Threats'
        )
        
        # Plot rolling average
        rolling_avg.plot(
            linestyle='-',
            linewidth=3,
            color='#ff7f0e',
            label='7-Day Moving Average'
        )
        
        # Enhanced styling
        plt.title('Threats Over Time with Trend Analysis', fontsize=18, fontweight='bold')
        plt.xlabel('Date', fontsize=14)
        plt.ylabel('Number of Threats', fontsize=14)
        plt.xticks(fontsize=12)
        plt.yticks(fontsize=12)
        plt.legend(fontsize=12)
        
        # Add grid for better readability
        plt.grid(True, linestyle='--', alpha=0.7)
        
        # Annotate key points (e.g., maximum values)
        max_point = threats_over_time.idxmax()
        max_value = threats_over_time.max()
        plt.annotate(
            f'Peak: {max_value}',
            xy=(max_point, max_value),
            xytext=(max_point, max_value + 1),
            arrowprops=dict(facecolor='black', shrink=0.05, width=1, headwidth=8),
            fontsize=12,
            ha='center'
        )
        
        # Tight layout
        plt.tight_layout()
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        
        # Save the chart with high DPI for better quality
        plt.savefig(output_file_path, dpi=300)
        logger.info(f"Enhanced threats over time chart saved to {output_file_path}")
        
        # Close the figure to free memory
        plt.close()
    
    except Exception as e:
        logger.error(f"Error plotting threats over time: {str(e)}")

def create_dash_dashboard(data):
    """
    Create an enhanced interactive dashboard using Dash with advanced filtering and layouts.
    
    Args:
        data: DataFrame containing threat data
    """
    try:
        # External stylesheets for better UI
        external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']
        
        # Initialize Dash app with better styling
        app = dash.Dash(
            __name__, 
            external_stylesheets=external_stylesheets,
            meta_tags=[{'name': 'viewport', 'content': 'width=device-width, initial-scale=1.0'}]
        )
        app.title = "Threat Intelligence Dashboard"
        
        # Create dropdown options for filtering
        technique_options = [{'label': technique, 'value': technique} 
                            for technique in sorted(data['technique_name'].unique())]
        
        source_options = [{'label': source, 'value': source} 
                         for source in sorted(data['source'].unique())]
        
        # Add tactic filtering if available
        tactic_options = []
        if 'tactic_name' in data.columns:
            tactic_options = [{'label': tactic, 'value': tactic} 
                             for tactic in sorted(data['tactic_name'].unique()) if pd.notna(tactic)]
        
        # Add time range options
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
                html.H1("Threat Intelligence Dashboard", className="app-header"),
                html.P("Interactive visualization of mapped threat intelligence data"),
                html.Hr()
            ], className="header"),
            
            # Filters section
            html.Div([
                html.H3("Filters", style={"margin-bottom": "20px"}),
                
                # First row of filters
                html.Div([
                    # Technique filter
                    html.Div([
                        html.Label("Filter by Technique"),
                        dcc.Dropdown(
                            id='technique-dropdown',
                            options=technique_options,
                            value=None,
                            placeholder="Select a technique",
                            clearable=True,
                            style={"width": "100%"}
                        ),
                    ], className="four columns"),
                    
                    # Source filter
                    html.Div([
                        html.Label("Filter by Source"),
                        dcc.Dropdown(
                            id='source-dropdown',
                            options=source_options,
                            value=None,
                            placeholder="Select a source",
                            clearable=True,
                            style={"width": "100%"}
                        ),
                    ], className="four columns"),
                    
                    # Tactic filter
                    html.Div([
                        html.Label("Filter by Tactic"),
                        dcc.Dropdown(
                            id='tactic-dropdown',
                            options=tactic_options,
                            value=None,
                            placeholder="Select a tactic",
                            clearable=True,
                            style={"width": "100%"}
                        ),
                    ], className="four columns"),
                ], className="row"),
                
                # Second row of filters
                html.Div([
                    # Date range filter
                    html.Div([
                        html.Label("Date Range"),
                        dcc.DatePickerRange(
                            id='date-range-picker',
                            min_date_allowed=min_date,
                            max_date_allowed=max_date,
                            start_date=min_date,
                            end_date=max_date,
                            display_format='YYYY-MM-DD'
                        ),
                    ], className="six columns"),
                    
                    # Top N selector
                    html.Div([
                        html.Label("Top N Techniques"),
                        dcc.Slider(
                            id='top-n-slider',
                            min=5,
                            max=20,
                            step=5,
                            value=10,
                            marks={i: str(i) for i in range(5, 25, 5)},
                            tooltip={"placement": "bottom", "always_visible": True}
                        ),
                    ], className="six columns"),
                ], className="row", style={"margin-top": "20px"}),
                
                # Apply filters button
                html.Div([
                    html.Button(
                        'Apply Filters',
                        id='apply-filters-button',
                        n_clicks=0,
                        className="button-primary",
                        style={"margin-top": "20px"}
                    ),
                    
                    # Reset filters button
                    html.Button(
                        'Reset Filters',
                        id='reset-filters-button',
                        n_clicks=0,
                        style={"margin-top": "20px", "margin-left": "20px"}
                    ),
                ], className="row", style={"margin-top": "10px", "text-align": "center"}),
                
                html.Hr()
                
            ], className="filters-container"),
            
            # Dashboard content with tabs for different visualizations
            html.Div([
                dcc.Tabs([
                    # Tab 1: Technique Distribution
                    dcc.Tab(label="Technique Distribution", children=[
                        html.Div([
                            dcc.Graph(
                                id='technique-distribution-graph',
                                style={"height": "500px"}
                            ),
                        ], className="graph-container")
                    ]),
                    
                    # Tab 2: Threats Over Time
                    dcc.Tab(label="Threats Over Time", children=[
                        html.Div([
                            dcc.Graph(
                                id='threats-over-time-graph',
                                style={"height": "500px"}
                            ),
                        ], className="graph-container")
                    ]),
                    
                    # Tab 3: Source Distribution
                    dcc.Tab(label="Source Distribution", children=[
                        html.Div([
                            dcc.Graph(
                                id='source-distribution-graph',
                                style={"height": "500px"}
                            ),
                        ], className="graph-container")
                    ]),
                    
                    # Tab 4: Tactic Distribution (if available)
                    dcc.Tab(label="Tactic Distribution", children=[
                        html.Div([
                            dcc.Graph(
                                id='tactic-distribution-graph',
                                style={"height": "500px"}
                            ),
                        ], className="graph-container")
                    ]),
                    
                    # Tab 5: Detailed Data Table
                    dcc.Tab(label="Data Table", children=[
                        html.Div([
                            dash_table.DataTable(
                                id='data-table',
                                columns=[
                                    {"name": "Technique", "id": "technique_name"},
                                    {"name": "Tactic", "id": "tactic_name"} if 'tactic_name' in data.columns else {"name": "ID", "id": "id"},
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
                ], id="dashboard-tabs")
            ], className="content-container"),
            
            # Footer section
            html.Div([
                html.Hr(),
                html.P("Threat Models and MITRE ATT&CK Mapping Tool © 2025", style={"text-align": "center"})
            ], className="footer")
            
        ], className="app-container")
        
        # Callback to update technique distribution graph
        @app.callback(
            Output('technique-distribution-graph', 'figure'),
            [Input('apply-filters-button', 'n_clicks')],
            [State('technique-dropdown', 'value'),
             State('source-dropdown', 'value'),
             State('tactic-dropdown', 'value'),
             State('date-range-picker', 'start_date'),
             State('date-range-picker', 'end_date'),
             State('top-n-slider', 'value')]
        )
        def update_technique_graph(n_clicks, selected_technique, selected_source, 
                                 selected_tactic, start_date, end_date, top_n):
            filtered_data = filter_data(data, selected_technique, selected_source, 
                                      selected_tactic, start_date, end_date)
            
            # Count occurrences of each technique
            technique_counts = filtered_data['technique_name'].value_counts().nlargest(top_n).reset_index()
            technique_counts.columns = ['technique_name', 'count']
            
            # Create the graph with Plotly
            fig = px.bar(
                technique_counts, 
                x='technique_name', 
                y='count',
                title=f"Top {top_n} Technique Distribution",
                labels={'technique_name': 'Technique', 'count': 'Count'},
                color='count',
                color_continuous_scale=viz_config.get('color_scheme', 'viridis'),
                template='plotly_white'
            )
            
            # Customize layout for better presentation
            fig.update_layout(
                xaxis_title="Technique",
                yaxis_title="Count",
                xaxis={'categoryorder':'total descending'},
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                height=500,
                margin=dict(l=50, r=50, t=80, b=80),
                xaxis_tickangle=-45
            )
            
            return fig
        
        # Callback to update threats over time graph
        @app.callback(
            Output('threats-over-time-graph', 'figure'),
            [Input('apply-filters-button', 'n_clicks')],
            [State('technique-dropdown', 'value'),
             State('source-dropdown', 'value'),
             State('tactic-dropdown', 'value'),
             State('date-range-picker', 'start_date'),
             State('date-range-picker', 'end_date')]
        )
        def update_time_graph(n_clicks, selected_technique, selected_source, 
                            selected_tactic, start_date, end_date):
            filtered_data = filter_data(data, selected_technique, selected_source, 
                                      selected_tactic, start_date, end_date)
            
            # Convert timestamp to datetime if it's not already
            if not pd.api.types.is_datetime64_any_dtype(filtered_data['timestamp']):
                filtered_data['timestamp'] = pd.to_datetime(filtered_data['timestamp'])
            
            # Group by day and count
            time_data = filtered_data.groupby(filtered_data['timestamp'].dt.date).size().reset_index()
            time_data.columns = ['date', 'count']
            
            # Calculate rolling average
            if len(time_data) > 7:
                # Create a Series for the rolling average
                rolling_series = pd.Series(time_data['count'].values, index=time_data['date'])
                rolling_avg = rolling_series.rolling(window=7, min_periods=1).mean()
                
                # Create a new DataFrame for the rolling average
                rolling_data = pd.DataFrame({
                    'date': rolling_series.index,
                    'rolling_avg': rolling_avg.values
                })
                
                # Create the graph with both lines
                fig = go.Figure()
                
                # Add the daily count line
                fig.add_trace(go.Scatter(
                    x=time_data['date'],
                    y=time_data['count'],
                    mode='lines+markers',
                    name='Daily Threats',
                    line=dict(color='#1f77b4', width=2),
                    marker=dict(size=5)
                ))
                
                # Add the rolling average line
                fig.add_trace(go.Scatter(
                    x=rolling_data['date'],
                    y=rolling_data['rolling_avg'],
                    mode='lines',
                    name='7-Day Moving Average',
                    line=dict(color='#ff7f0e', width=3)
                ))
                
            else:
                # Create a simpler graph if we don't have enough data for rolling average
                fig = px.line(
                    time_data, 
                    x='date', 
                    y='count',
                    markers=True,
                    template='plotly_white'
                )
            
            # Customize layout
            fig.update_layout(
                title="Threats Over Time",
                xaxis_title="Date",
                yaxis_title="Number of Threats",
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                height=500,
                margin=dict(l=50, r=50, t=80, b=50),
                hovermode="x unified",
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=1.02,
                    xanchor="right",
                    x=1
                )
            )
            
            return fig
        
        # Callback to update source distribution graph
        @app.callback(
            Output('source-distribution-graph', 'figure'),
            [Input('apply-filters-button', 'n_clicks')],
            [State('technique-dropdown', 'value'),
             State('source-dropdown', 'value'),
             State('tactic-dropdown', 'value'),
             State('date-range-picker', 'start_date'),
             State('date-range-picker', 'end_date')]
        )
        def update_source_graph(n_clicks, selected_technique, selected_source, 
                              selected_tactic, start_date, end_date):
            filtered_data = filter_data(data, selected_technique, selected_source, 
                                      selected_tactic, start_date, end_date)
            
            # Count occurrences of each source
            source_counts = filtered_data['source'].value_counts().reset_index()
            source_counts.columns = ['source', 'count']
            
            # Create the pie chart
            fig = px.pie(
                source_counts, 
                values='count', 
                names='source',
                title="Source Distribution",
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Bold
            )
            
            # Customize layout
            fig.update_layout(
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                height=500,
                margin=dict(l=50, r=50, t=80, b=50),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.2,
                    xanchor="center",
                    x=0.5
                )
            )
            
            return fig
        
        # Callback to update tactic distribution graph
        @app.callback(
            Output('tactic-distribution-graph', 'figure'),
            [Input('apply-filters-button', 'n_clicks')],
            [State('technique-dropdown', 'value'),
             State('source-dropdown', 'value'),
             State('tactic-dropdown', 'value'),
             State('date-range-picker', 'start_date'),
             State('date-range-picker', 'end_date'),
             State('top-n-slider', 'value')]
        )
        def update_tactic_graph(n_clicks, selected_technique, selected_source, 
                              selected_tactic, start_date, end_date, top_n):
            filtered_data = filter_data(data, selected_technique, selected_source, 
                                      selected_tactic, start_date, end_date)
            
            # Check if tactic column exists
            if 'tactic_name' in filtered_data.columns:
                # Remove any NaN values
                tactic_data = filtered_data.dropna(subset=['tactic_name'])
                
                # Count occurrences of each tactic
                tactic_counts = tactic_data['tactic_name'].value_counts().nlargest(top_n).reset_index()
                tactic_counts.columns = ['tactic_name', 'count']
                
                # Create the bar chart
                fig = px.bar(
                    tactic_counts, 
                    x='tactic_name', 
                    y='count',
                    title=f"Top {top_n} Tactic Distribution",
                    labels={'tactic_name': 'Tactic', 'count': 'Count'},
                    color='count',
                    color_continuous_scale=viz_config.get('color_scheme', 'viridis'),
                    template='plotly_white'
                )
                
                # Customize layout
                fig.update_layout(
                    xaxis_title="Tactic",
                    yaxis_title="Count",
                    xaxis={'categoryorder':'total descending'},
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    height=500,
                    margin=dict(l=50, r=50, t=80, b=80),
                    xaxis_tickangle=-45
                )
            else:
                # Create an empty figure with a message if tactic data is not available
                fig = go.Figure()
                fig.add_annotation(
                    text="Tactic data is not available",
                    xref="paper", yref="paper",
                    x=0.5, y=0.5, showarrow=False,
                    font=dict(size=20)
                )
            
            return fig
        
        # Callback to update data table
        @app.callback(
            Output('data-table', 'data'),
            [Input('apply-filters-button', 'n_clicks')],
            [State('technique-dropdown', 'value'),
             State('source-dropdown', 'value'),
             State('tactic-dropdown', 'value'),
             State('date-range-picker', 'start_date'),
             State('date-range-picker', 'end_date')]
        )
        def update_data_table(n_clicks, selected_technique, selected_source, 
                            selected_tactic, start_date, end_date):
            filtered_data = filter_data(data, selected_technique, selected_source, 
                                      selected_tactic, start_date, end_date)
            
            # Format the data for the table
            table_data = filtered_data.copy()
            
            # Convert timestamp to string format for display
            if 'timestamp' in table_data.columns:
                table_data['timestamp_str'] = table_data['timestamp'].dt.strftime('%Y-%m-%d')
            
            # Limit description length
            if 'description' in table_data.columns:
                table_data['description'] = table_data['description'].apply(
                    lambda x: x[:100] + '...' if isinstance(x, str) and len(x) > 100 else x
                )
            
            # Return only the columns we need
            columns_to_display = [
                'technique_name', 
                'tactic_name' if 'tactic_name' in table_data.columns else 'id',
                'source', 
                'timestamp_str', 
                'description'
            ]
            
            return table_data[columns_to_display].to_dict('records')
        
        # Callback to reset filters
        @app.callback(
            [Output('technique-dropdown', 'value'),
             Output('source-dropdown', 'value'),
             Output('tactic-dropdown', 'value'),
             Output('date-range-picker', 'start_date'),
             Output('date-range-picker', 'end_date'),
             Output('top-n-slider', 'value')],
            [Input('reset-filters-button', 'n_clicks')]
        )
        def reset_filters(n_clicks):
            # Only reset if button was clicked
            if n_clicks > 0:
                return None, None, None, min_date, max_date, 10
            
            # Return the current values if button wasn't clicked (prevents resetting on load)
            return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update
        
        # Helper function to filter the data based on selected filters
        def filter_data(data, technique, source, tactic, start_date, end_date):
            filtered_data = data.copy()
            
            # Apply technique filter
            if technique:
                filtered_data = filtered_data[filtered_data['technique_name'] == technique]
            
            # Apply source filter
            if source:
                filtered_data = filtered_data[filtered_data['source'] == source]
            
            # Apply tactic filter
            if tactic and 'tactic_name' in filtered_data.columns:
                filtered_data = filtered_data[filtered_data['tactic_name'] == tactic]
            
            # Apply date filter
            if start_date and end_date and 'timestamp' in filtered_data.columns:
                start_date = pd.to_datetime(start_date)
                end_date = pd.to_datetime(end_date)
                filtered_data = filtered_data[
                    (filtered_data['timestamp'] >= start_date) & 
                    (filtered_data['timestamp'] <= end_date)
                ]
            
            return filtered_data
        
        # Add custom CSS for better styling
        app.index_string = '''
        <!DOCTYPE html>
        <html>
            <head>
                {%metas%}
                <title>{%title%}</title>
                {%favicon%}
                {%css%}
                <style>
                    body {
                        font-family: "Segoe UI", Arial, sans-serif;
                        margin: 0;
                        background-color: #f8f9fa;
                    }
                    .app-container {
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: white;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }
                    .app-header {
                        margin-top: 0;
                        color: #2c3e50;
                    }
                    .header {
                        margin-bottom: 20px;
                        text-align: center;
                    }
                    .filters-container {
                        background-color: #f8f9fa;
                        padding: 20px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                    }
                    .graph-container {
                        background-color: white;
                        padding: 15px;
                        border-radius: 5px;
                        box-shadow: 0 0 5px rgba(0,0,0,0.05);
                    }
                    .table-container {
                        margin-top: 20px;
                        margin-bottom: 20px;
                    }
                    .button-primary {
                        background-color: #3498db;
                        color: white;
                    }
                    .footer {
                        margin-top: 20px;
                        color: #7f8c8d;
                    }
                </style>
            </head>
            <body>
                {%app_entry%}
                <footer>
                    {%config%}
                    {%scripts%}
                    {%renderer%}
                </footer>
            </body>
        </html>
        '''
        
        # Run the app
        app.run_server(debug=True)
        
    except Exception as e:
        logger.error(f"Error creating enhanced Dash dashboard: {str(e)}")

def generate_static_visualizations():
    """
    Generate static visualizations (maps and charts).
    """
    # Fetch data
    data = fetch_data_from_db()
    
    if data.empty:
        # Try to fetch from file if database is empty
        data = fetch_data_from_file('data/processed/mapped_threat_data.json')
    
    if data.empty:
        logger.error("No data available for visualization")
        return
    
    # Create visualizations
    create_interactive_map(data)
    plot_threat_types(data)
    plot_threats_over_time(data)
    
    logger.info("Static visualizations generated successfully")

def run_interactive_dashboard():
    """
    Run the interactive Dash dashboard.
    """
    # Fetch data
    data = fetch_data_from_db()
    
    if data.empty:
        # Try to fetch from file if database is empty
        data = fetch_data_from_file('data/processed/mapped_threat_data.json')
    
    if data.empty:
        logger.error("No data available for dashboard")
        return
    
    # Create and run dashboard
    create_dash_dashboard(data)

if __name__ == "__main__":
    # Generate static visualizations
    generate_static_visualizations()
    
    # Uncomment to run interactive dashboard
    # run_interactive_dashboard()
