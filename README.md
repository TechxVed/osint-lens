# OSINT-Lens

OSINT-Lens is a command-line OSINT aggregation and correlation framework. It brings multiple OSINT tools into one workflow, normalizes their results into a common format, correlates related findings using transparent rules, and displays results in the terminal. Scan history is stored in SQLite, with optional HTML reports.

## Features

- Run supported OSINT modules from one terminal.
- Normalize results into a shared `Finding` format.
- Correlate related findings using rule-based logic.
- Store scan history, findings, and alerts in SQLite.
- Display results with Rich and generate optional HTML reports.
- Integrate API-based intelligence and Docker-isolated tools.

## OSINT modules

| Tool | Integration | Purpose |
|---|---|---|
| Shodan | API | Internet-facing host and service intelligence |
| theHarvester | Docker | Domain-related reconnaissance, such as emails and hostnames |
| Subfinder | Docker | Subdomain discovery |
| Sherlock | Docker | Username and account presence searches across online services |
| Sublist3r | Docker | Subdomain enumeration |
| `mock_example` | Built-in test module | Generate synthetic findings to test the framework without external services |

The five OSINT tools above are the project's planned integrations. A tool is usable through OSINT-Lens only after its plugin and required configuration are implemented. The mock module is for testing the framework and is not an OSINT data source.

## How it works

```text
CLI
 ↓
Target validation and authorization
 ↓
Plugin registry and orchestrator
 ↓
OSINT tools and APIs
 ↓
Parsing and normalization
 ↓
Rule-based correlation
 ↓
SQLite storage
 ↓
Rich terminal output / optional HTML report
```

## Project structure

```text
osint-lens/
├── main.py
├── requirements.txt
├── .env.example
├── core/                  # Models, validation, registry, orchestration,
│                          # normalization, and correlation
├── plugins/
│   ├── mock_example_plugin.py
│   ├── api_plugins/       # API integrations
│   └── docker_plugins/    # Docker-based tool integrations
├── docker/                # Docker image definitions
├── database/              # SQLite schema and data access
├── reports/               # HTML report generator and template
├── cli/                   # CLI commands and terminal output
└── tests/
```

## Installation

### Requirements

- Python 3.11 or newer
- Git
- Docker for Docker-based tools
- API credentials for services that require them

### Set up on Kali Linux / Debian-based systems

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip git

git clone https://github.com/TechxVed/osint-lens.git
cd osint-lens

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

cp .env.example .env
```

## Configuration

Add the API credentials required by the integrations you use to `.env`. For Shodan:

```env
SHODAN_API_KEY=your_shodan_api_key
```

Keep `.env` private and do not commit API keys. The built-in `mock_example` module does not require external credentials.

## Usage

Run commands from the project root with the virtual environment activated.

```bash
# Show available commands
python main.py --help

# List modules and their availability
python main.py modules

# Run a mock scan to check the workflow
python main.py scan --target example.com --modules mock_example

# Run selected available modules
python main.py scan --target example.com --modules mock_example,shodan

# View scan history
python main.py history

# Generate a report for an existing scan
python main.py report <scan_id>

# Show version
python main.py version
```

Use only targets you are authorized to assess. Use `--yes` only when authorization has already been confirmed.

## Docker and AWS

Docker is used to isolate command-line tools. The project's intended deployment uses an AWS EC2 instance as the Docker execution environment. Install Docker on the EC2 instance, make the project and its required images available there, and configure credentials securely. API-based integrations such as Shodan do not need to run inside Docker.

## Troubleshooting

| Issue | What to check |
|---|---|
| `ModuleNotFoundError` | Activate `.venv` and run commands from the project root. |
| A module is unavailable | Check its required configuration and whether its plugin/image has been set up. |
| Shodan is unavailable | Check that `.env` exists and `SHODAN_API_KEY` is set correctly. |
| Docker permission denied | Confirm Docker is running and your user can access it. |
| SQLite database is locked | Avoid multiple processes writing to the same database simultaneously. |
