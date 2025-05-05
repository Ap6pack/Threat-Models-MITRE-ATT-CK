# Threat Models and MITRE ATT&CK Mapping Tool

This Python tool automates the process of updating threat models and mapping them to the MITRE ATT&CK framework based on the latest threat intelligence data. The tool fetches data from various threat intelligence sources, including the MITRE ATT&CK API, AlienVault OTX, and VirusTotal, and uses machine learning and NLP techniques to map observed threat behaviors to known attack techniques. This enhances situational awareness and aids in effective defense strategy formulation.

## Features

- **Real-Time Threat Intelligence Integration**: Integrates multiple threat intelligence sources, including MITRE ATT&CK, AlienVault OTX, and VirusTotal.
- **Advanced Mapping Algorithms**: Uses machine learning models and NLP for accurate mapping of threat data to MITRE ATT&CK techniques.
- **Visualization**: Provides an interactive map and visualizations, including threat type distributions and threats over time.
- **Automation and Scheduling**: Supports automated fetching, mapping, and model updates at regular intervals.
- **Customizable Threat Models**: Allows customization of threat models and mappings based on specific organizational needs.
- **Detailed Reporting**: Generates detailed HTML reports with embedded metrics, analytics, and visualizations.
- **SIEM and SOAR Integration**: Integrates with SIEM and SOAR platforms for enhanced incident response automation.

## Project Structure

The project follows a modular structure with clear separation of concerns:

```
Threat-Models-MITRE-ATT&CK/
├── config/                  # Configuration files
│   └── settings.yaml        # Main configuration file
├── data/                    # Data storage
│   ├── raw/                 # Raw data from threat intelligence sources
│   └── processed/           # Processed and normalized data
├── docs/                    # Documentation
│   └── architecture.md      # System architecture document
├── integrations/            # Integration with external systems
│   ├── siem/                # SIEM integration
│   └── soar/                # SOAR integration
├── logs/                    # Application logs
├── models/                  # Machine learning models
├── reports/                 # Generated reports
│   └── report_template.html # Report template
├── scripts/                 # Main application scripts
│   ├── data_ingestion/      # Data ingestion scripts
│   ├── mapping/             # Mapping algorithms
│   ├── reporting/           # Report generation
│   ├── visualization/       # Visualization scripts
│   └── main.py              # Main entry point
└── tests/                   # Unit and integration tests
```

## Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- Required Python packages (listed in `requirements.txt`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Ap6pack/Threat-Models-MITRE-ATT&CK.git
   cd Threat-Models-MITRE-ATT&CK
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up the PostgreSQL database:
   ```bash
   # Create a database named 'threat_intelligence'
   createdb threat_intelligence
   ```

5. Update the configuration file:
   - Open `config/settings.yaml` and update the database credentials and API keys.

## Usage

### Running the Full Workflow

To run the full workflow (data ingestion, mapping, visualization, and reporting):

```bash
python scripts/main.py --all
```

### Running Specific Components

To run specific components of the workflow:

```bash
# Data ingestion only
python scripts/main.py --ingest

# Mapping only
python scripts/main.py --map

# Visualization only
python scripts/main.py --visualize

# Reporting only
python scripts/main.py --report

# Run with interactive dashboard
python scripts/main.py --all --interactive
```

### Command-Line Arguments

- `--ingest`: Run data ingestion process
- `--map`: Run mapping process
- `--visualize`: Run visualization process
- `--report`: Run reporting process
- `--interactive`: Run interactive dashboard
- `--all`: Run full workflow

## Configuration

The tool is configured using the `config/settings.yaml` file. This file contains settings for:

- API URLs and endpoints
- API keys
- File paths
- Database configuration
- Scheduling configuration
- Machine learning configuration
- Visualization configuration
- Reporting configuration

## Development

### Running Tests

To run the tests:

```bash
pytest
```

### Code Style

This project uses Black for code formatting, Flake8 for linting, and isort for import sorting:

```bash
# Format code
black scripts tests

# Check code style
flake8 scripts tests

# Sort imports
isort scripts tests
```

## Documentation

For more detailed information about the system architecture, see the [Architecture Document](docs/architecture.md).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
