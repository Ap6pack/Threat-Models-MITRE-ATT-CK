# Folder and File Structure

This document provides an overview of the folder and file structure of the Threat Models and MITRE ATT&CK Mapping Tool project.

## Project Structure

The project follows a modular structure with clear separation of concerns:

```
Threat-Models-MITRE-ATT&CK/
├── config/                  # Configuration files
│   └── settings.yaml        # Main configuration file
├── data/                    # Data storage
│   ├── raw/                 # Raw data from threat intelligence sources
│   │   ├── mitre_attack_data.json    # Raw MITRE ATT&CK data
│   │   ├── otx_attack_data.json      # Raw AlienVault OTX data
│   │   └── example_threat_data.json  # Example threat data for testing
│   └── processed/           # Processed and normalized data
│       ├── normalized_mitre_data.json    # Normalized MITRE ATT&CK data
│       ├── normalized_otx_data.json      # Normalized OTX data
│       ├── combined_threat_data.json     # Combined threat data
│       ├── mapped_threat_data.json       # Mapped threat data
│       └── mappings.csv                  # Mappings in CSV format
├── docs/                    # Documentation
│   ├── architecture.md      # System architecture document
│   ├── dashboard_usage.md   # Dashboard usage guide
│   ├── folder_file_structure.md  # This document
│   ├── usability_testing.md      # Usability testing protocol
│   └── usability_results.md      # Usability testing results
├── integrations/            # Integration with external systems
│   ├── siem/                # SIEM integration
│   │   └── siem_integration.py   # SIEM integration script
│   └── soar/                # SOAR integration
│       └── soar_integration.py   # SOAR integration script
├── logs/                    # Application logs
│   └── app.log              # Main application log
├── models/                  # Machine learning models
│   ├── threat_mapping_model.pkl       # Trained model
│   └── threat_mapping_vectorizer.pkl  # TF-IDF vectorizer
├── reports/                 # Generated reports
│   ├── report_template.html           # Report template
│   ├── threat_report.csv              # CSV report
│   ├── threat_report.html             # HTML report
│   ├── threat_report.json             # JSON report
│   ├── threat_report.pdf              # PDF report
│   ├── threat_types_distribution.png  # Threat types visualization
│   └── threats_over_time.png          # Threats over time visualization
├── scripts/                 # Main application scripts
│   ├── __init__.py          # Package initialization
│   ├── main.py              # Main entry point
│   ├── data_ingestion/      # Data ingestion scripts
│   │   ├── __init__.py      # Package initialization
│   │   ├── consolidated_ingest_data.py  # Consolidated data ingestion
│   │   ├── ingest_data.py              # Data ingestion
│   │   ├── normalize_data.py           # Data normalization
│   │   └── store_data_in_db.py         # Database storage
│   ├── mapping/             # Mapping algorithms
│   │   ├── __init__.py      # Package initialization
│   │   ├── consolidated_mapping_algorithm.py  # Consolidated mapping
│   │   └── mapping_algorithm.py              # Mapping algorithm
│   ├── reporting/           # Report generation
│   │   ├── __init__.py      # Package initialization
│   │   └── generate_reports.py         # Report generation
│   └── visualization/       # Visualization scripts
│       ├── __init__.py      # Package initialization
│       ├── consolidated_dashboard.py   # Consolidated dashboard
│       ├── dashboard.py                # Dashboard
│       ├── error_performance.py        # Error performance visualization
│       └── relationship_visualization.py  # Relationship visualization
├── static/                  # Static files
│   └── responsive_styles.css  # CSS styles
├── tests/                   # Unit and integration tests
│   ├── __init__.py          # Package initialization
│   ├── test_data_ingestion.py         # Data ingestion tests
│   ├── test_ingest_data.py            # Ingest data tests
│   ├── test_mapping_algorithm.py      # Mapping algorithm tests
│   ├── test_normalize_data.py         # Normalize data tests
│   ├── test_soar_integration.py       # SOAR integration tests
│   └── test_visualization.py          # Visualization tests
├── .gitignore               # Git ignore file
├── LICENSE                  # MIT License
├── README.md                # Project README
└── requirements.txt         # Python dependencies
```

## Component Details

### Configuration

The `config/` directory contains configuration files for the application:

- `settings.yaml`: Main configuration file with settings for API URLs, database, visualization, etc.

### Data

The `data/` directory stores raw and processed data:

- `raw/`: Raw data from threat intelligence sources
  - `mitre_attack_data.json`: Raw MITRE ATT&CK data
  - `otx_attack_data.json`: Raw AlienVault OTX data
  - `example_threat_data.json`: Example threat data for testing

- `processed/`: Processed and normalized data
  - `normalized_mitre_data.json`: Normalized MITRE ATT&CK data
  - `normalized_otx_data.json`: Normalized OTX data
  - `combined_threat_data.json`: Combined threat data
  - `mapped_threat_data.json`: Mapped threat data
  - `mappings.csv`: Mappings in CSV format

### Documentation

The `docs/` directory contains project documentation:

- `architecture.md`: System architecture document
- `dashboard_usage.md`: Dashboard usage guide
- `folder_file_structure.md`: This document
- `usability_testing.md`: Usability testing protocol
- `usability_results.md`: Usability testing results

### Integrations

The `integrations/` directory contains scripts for integrating with external systems:

- `siem/`: SIEM integration
  - `siem_integration.py`: SIEM integration script

- `soar/`: SOAR integration
  - `soar_integration.py`: SOAR integration script

### Logs

The `logs/` directory stores application logs:

- `app.log`: Main application log

### Models

The `models/` directory stores machine learning models:

- `threat_mapping_model.pkl`: Trained model
- `threat_mapping_vectorizer.pkl`: TF-IDF vectorizer

### Reports

The `reports/` directory contains generated reports and visualizations:

- `report_template.html`: Report template
- `threat_report.csv`: CSV report
- `threat_report.html`: HTML report
- `threat_report.json`: JSON report
- `threat_report.pdf`: PDF report
- `threat_types_distribution.png`: Threat types visualization
- `threats_over_time.png`: Threats over time visualization

### Scripts

The `scripts/` directory contains the main application scripts:

- `main.py`: Main entry point

- `data_ingestion/`: Data ingestion scripts
  - `consolidated_ingest_data.py`: Consolidated data ingestion
  - `ingest_data.py`: Data ingestion
  - `normalize_data.py`: Data normalization
  - `store_data_in_db.py`: Database storage

- `mapping/`: Mapping algorithms
  - `consolidated_mapping_algorithm.py`: Consolidated mapping
  - `mapping_algorithm.py`: Mapping algorithm

- `reporting/`: Report generation
  - `generate_reports.py`: Report generation

- `visualization/`: Visualization scripts
  - `consolidated_dashboard.py`: Consolidated dashboard
  - `dashboard.py`: Dashboard
  - `error_performance.py`: Error performance visualization
  - `relationship_visualization.py`: Relationship visualization

### Static

The `static/` directory contains static files:

- `responsive_styles.css`: CSS styles

### Tests

The `tests/` directory contains unit and integration tests:

- `test_data_ingestion.py`: Data ingestion tests
- `test_ingest_data.py`: Ingest data tests
- `test_mapping_algorithm.py`: Mapping algorithm tests
- `test_normalize_data.py`: Normalize data tests
- `test_soar_integration.py`: SOAR integration tests
- `test_visualization.py`: Visualization tests

## File Relationships

- `main.py` is the entry point that calls functions from the other modules.
- Data flows from `data_ingestion` to `mapping` to `visualization` and `reporting`.
- The `integrations` directory contains scripts for integrating with external systems.
- The `models` directory stores trained machine learning models used by the mapping algorithms.
- The `reports` directory contains generated reports and visualizations.
- The `tests` directory contains unit and integration tests for the various components.
