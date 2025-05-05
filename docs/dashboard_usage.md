# Threat Mapping Dashboard User Guide

This document provides guidance on using the MITRE ATT&CK Threat Mapping Dashboard, a powerful visualization tool for threat intelligence data mapped to the MITRE ATT&CK framework.

## Table of Contents

1. [Overview](#overview)
2. [Getting Started](#getting-started)
3. [Dashboard Features](#dashboard-features)
4. [Filtering Data](#filtering-data)
5. [Visualization Tabs](#visualization-tabs)
6. [Advanced Options](#advanced-options)
7. [Exporting Data](#exporting-data)
8. [Technical Details](#technical-details)
9. [Troubleshooting](#troubleshooting)

## Overview

The Threat Mapping Dashboard provides an interactive interface for exploring threat intelligence data that has been mapped to the MITRE ATT&CK framework. It visualizes relationships between threats, techniques, and tactics, allowing security analysts to identify patterns, trends, and areas of concern.

Key capabilities include:
- Filtering data by technique, source, tactic, and time period
- Multiple visualization types (bar charts, treemaps, pie charts)
- Time-series analysis of threat activity
- Relationship mapping between techniques and tactics
- Detailed data tables for in-depth analysis
- Data export functionality

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Required Python packages (listed in `requirements.txt`)
- PostgreSQL database with threat intelligence data

### Running the Dashboard

The dashboard can be launched in several ways:

1. **From the main application:**
   ```bash
   python scripts/main.py --visualize --interactive
   ```

2. **Directly from the dashboard script:**
   ```bash
   python scripts/visualization/dashboard.py
   ```

3. **From the consolidated dashboard script:**
   ```bash
   python scripts/visualization/consolidated_dashboard.py
   ```

Once launched, the dashboard will be accessible in your web browser at `http://127.0.0.1:8050/`.

## Dashboard Features

### Main Components

The dashboard consists of the following main areas:

1. **Header** - Displays the dashboard title and summary statistics
2. **Filter Panel** - Contains all filtering options
3. **Visualization Area** - Shows the selected visualization
4. **Detail Panel** - Displays detailed information about selected techniques

### Data Source

The dashboard retrieves data from:
1. The PostgreSQL database (primary source)
2. JSON files in the `data/processed/` directory (fallback if database unavailable)

## Filtering Data

The filter panel allows you to refine the displayed data:

### Basic Filters

- **Technique** - Filter by specific MITRE ATT&CK technique
- **Source** - Filter by threat intelligence source (MITRE ATT&CK, AlienVault OTX, VirusTotal, etc.)
- **Tactic** - Filter by MITRE ATT&CK tactic
- **Date Range** - Filter by time period

### Using Filters

1. Select your desired filter values from the dropdowns/date pickers
2. Click "Apply Filters" to update all visualizations
3. Click "Reset Filters" to clear all selections

Filters work across all tabs - when you apply filters, all visualizations update to reflect your selections.

## Visualization Tabs

The dashboard includes multiple visualization tabs:

### Technique Analysis

The primary visualization showing the distribution of MITRE ATT&CK techniques. This view helps identify the most prevalent techniques in your threat data.

- **Default View**: Bar chart showing technique counts
- **Alternate Views**: Treemap or pie chart (selectable via Advanced Options)
- **Interaction**: Click on a technique bar/segment to see detailed information

### Timeline Analysis

This view shows threat activity over time, helping identify trends, spikes, or periodic patterns in threat data.

- **Primary Graph**: Line chart showing daily threat counts
- **Secondary Line**: 7-day moving average (when sufficient data is available)
- **Interaction**: Hover over points to see specific values, zoom/pan for detailed exploration

### Relationship Analysis

This visualization maps the relationships between techniques and tactics, showing which techniques are associated with which tactics.

- **Display Method**: Heatmap with tactics on one axis and techniques on the other
- **Color Intensity**: Indicates frequency of the relationship
- **Insight Value**: Helps identify which techniques cross multiple tactical phases

### Data Table

A detailed tabular view of the data for more in-depth analysis.

- **Functionality**: Sort, filter, and page through records
- **Columns**: Technique name, tactic, source, date, and description
- **Usage**: Useful for detailed inspection of specific data points

## Advanced Options

The dashboard includes several advanced options for customizing visualizations:

### Chart Types

For the Technique Analysis tab, you can choose from three chart types:

1. **Bar Chart** - Best for precise comparison between techniques
2. **Treemap** - Useful for hierarchical visualization (techniques grouped by tactic)
3. **Pie Chart** - Ideal for showing proportional distribution of techniques

To change the chart type:
1. Go to the Advanced Options section in the filter panel
2. Select your preferred chart type from the radio buttons
3. Click "Apply Filters" to update the visualization

### Color Schemes

You can customize the color scheme used in visualizations:

1. Select a color scheme from the dropdown in the Advanced Options section
2. Available options include: Viridis, Plasma, Inferno, Cividis, and Blues
3. Click "Apply Filters" to apply the selected color scheme

Different color schemes may be better suited for different types of data or for accessibility purposes.

## Exporting Data

The dashboard allows you to export data for further analysis or reporting:

### Export as CSV

1. Apply any desired filters to refine the data
2. Click the "Export as CSV" button in the filter panel
3. Save the file to your desired location

The exported CSV will contain all data matching your current filter selections.

### Export as PNG

To export visualizations as images:

1. Navigate to the visualization you want to export
2. Click the "Export as PNG" button
3. The visualization will be saved as a PNG file

Alternatively, you can use the camera icon in the visualization's toolbar to customize and download the image.

## Technical Details

### Data Processing

The dashboard performs the following data processing operations:

1. **Data Fetching**: Connects to PostgreSQL database or reads from JSON files
2. **Data Filtering**: Applies user-selected filters to the dataset
3. **Data Aggregation**: Groups and counts data for visualizations
4. **Time Series Analysis**: Calculates trends and moving averages

### Dashboard Architecture

The dashboard is built using:

- **Dash**: A Python framework for building web applications
- **Plotly**: For interactive visualizations
- **SQLAlchemy**: For database connectivity
- **Pandas**: For data manipulation

### Performance Considerations

For optimal performance:
- Limit date ranges to reasonable periods (e.g., 6 months) when dealing with large datasets
- Use filters to reduce the data volume when experiencing slowness
- Consider increasing server resources for large threat intelligence databases

## Troubleshooting

### Common Issues

#### No Data Displayed

**Possible causes:**
- Database connection issue
- No data matching current filters
- Data format problems

**Solutions:**
1. Reset filters using the "Reset Filters" button
2. Check database connection settings in `config/settings.yaml`
3. Verify that data exists in the expected format

#### Slow Dashboard Performance

**Possible causes:**
- Large dataset
- Complex queries
- Limited server resources

**Solutions:**
1. Apply more restrictive filters to reduce data volume
2. Close other applications to free up resources
3. Consider database optimization (indexing, etc.)

#### Visualization Not Updating

**Possible causes:**
- Browser cache issues
- JavaScript errors
- Network interruptions

**Solutions:**
1. Click the "Apply Filters" button to force update
2. Refresh the browser page
3. Check browser console for errors

### Getting Help

If you encounter persistent issues:

1. Check the application logs in the `logs/` directory
2. Refer to the technical documentation in `docs/architecture.md`
3. Contact your system administrator or the development team for assistance

## Conclusion

The Threat Mapping Dashboard provides a powerful set of tools for analyzing and visualizing threat intelligence data mapped to the MITRE ATT&CK framework. By effectively using filters, exploring different visualization types, and leveraging the data export functionality, security analysts can gain valuable insights into the threat landscape and inform their defensive strategies.