# ReconMap 🗺️

**Automated Information Gathering and Attack-Surface Enumeration Tool**

[![ReconMap Tests](https://github.com/Maheswari-2026/ReconMap/actions/workflows/tests.yml/badge.svg)](https://github.com/Maheswari-2026/ReconMap/actions/workflows/tests.yml)

ReconMap is a Python-based cybersecurity learning project that collects publicly observable domain information, discovers hostnames through Certificate Transparency data, checks HTTP/HTTPS availability, and generates structured reconnaissance reports.

It is designed to help learners understand reconnaissance workflows and attack-surface visibility.

## Features

- **DNS enumeration:** Collect A, AAAA, NS, MX, TXT, and CNAME records.
- **Certificate Transparency:** Discover hostnames from publicly available certificate records.
- **HTTP/HTTPS discovery:** Check web-service availability on discovered in-scope hostnames.
- **Scope control:** Restrict active HTTP checks to the target domain and its subdomains.
- **Passive mode:** Run reconnaissance without active HTTP requests.
- **JSON and CSV reports:** Export structured findings for further analysis.
- **Automated testing:** Run tests through GitHub Actions.

## Technology Stack

- Python
- dnspython
- HTTPX
- pytest
- Git and GitHub Actions

## Architecture

```text
                Target Domain
                      |
          +-----------+-----------+
          |                       |
     DNS Collector        Certificate Collector
          |                       |
          +-----------+-----------+
                      |
                Asset Collection
                      |
               Scope Validation
                      |
             HTTP/HTTPS Discovery
                 (optional)
                      |
              Attack-Surface Analysis
                      |
              +-------+-------+
              |               |
           JSON Report      CSV Report
```

## Installation

### Requirements

- Python 3.11 or newer
- Git

### Windows Setup

Clone the repository:

```powershell
git clone https://github.com/Maheswari-2026/ReconMap.git
cd ReconMap
```

Create a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the dependencies:

```powershell
python -m pip install --upgrade pip
pip install dnspython httpx pytest
```

## Usage

### Display help

```powershell
python -m reconmap --help
```

### Passive reconnaissance

```powershell
python -m reconmap example.com --passive-only
```

Passive mode collects DNS and Certificate Transparency information without performing active HTTP checks.

### Standard reconnaissance

```powershell
python -m reconmap example.com
```

Standard mode also attempts HTTP/HTTPS checks on discovered in-scope hostnames.

Replace `example.com` with a domain you own or are explicitly authorized to assess.

## Output Reports

ReconMap generates JSON and CSV reports in the `results/` directory:

```text
results/
├── example.com-report.json
└── example.com-report.csv
```

The reports include discovered assets, DNS information, web-service observations, and attack-surface findings.

Generated reports may contain sensitive information about the assessed environment. Review them before sharing.

## Testing

Run the test suite locally:

```powershell
pytest -q
```

GitHub Actions automatically runs the tests on pushes and pull requests to the configured branches.

## Responsible Use

ReconMap is intended for education and authorized security assessment.

- Only assess domains you own or have explicit permission to test.
- Respect applicable laws, service terms, and rate limits.
- Publicly available information does not imply permission to perform active checks.
- Do not use this project to exploit systems or disrupt services.

## Project Status

ReconMap is an educational project under active development. Its results are observations, not proof that a system is secure or vulnerable.

## Author

**Maheswari Cherukupalli**

Cybersecurity learning project focused on reconnaissance, DNS analysis, and attack-surface visibility.