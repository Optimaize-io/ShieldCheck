# Lead Scout - NIS2 OSINT Scanner

A Python tool that scans Dutch company domains for public security weaknesses and NIS2 compliance gaps using Open Source Intelligence (OSINT) techniques.

## Purpose

This tool helps identify potential leads for Nomios by finding companies with:
- Poor email security (missing SPF, DMARC, DKIM)
- Internet-exposed vulnerabilities (via Shodan)
- SSL/TLS certificate issues
- Lack of security communication on their website
- No visible NIS2 preparedness

**Key insight:** Lower scores = hotter leads. Companies with security gaps *need* cybersecurity services.

## Quick Start

### Installation

```bash
cd lead-scout
pip install -r requirements.txt
```

### Run a Demo Scan

```bash
python scout.py --input data/sample_companies.csv --output output/report.md
```

### Scan a Single Company

```bash
python scout.py --domain example.nl --name "Example BV" --sector "Manufacturing" --employees 500
```

## Features

### Scanners

1. **DNS Scanner** - Checks SPF, DMARC, and DKIM records for email authentication
2. **Shodan Scanner** - Uses free Shodan InternetDB API to find open ports and known CVEs
3. **SSL Scanner** - Validates certificates, expiry dates, and TLS versions
4. **Website Scanner** - Analyzes website content for security keywords and NIS2 mentions

### Scoring

Each company is scored on 5 dimensions (0-2 points each, total 0-10):

| Dimension | 0 | 1 | 2 |
|-----------|---|---|---|
| Email Security | Poor/missing | Partial | Full protection |
| Technical Hygiene | 5+ CVEs or risky ports | Some CVEs | Clean |
| TLS Certificate | Invalid/expiring | Valid but old | Valid + modern |
| Security Communication | Nothing found | Some mentions | Dedicated page |
| NIS2 Readiness | No NIS2/compliance | ISO mentioned | NIS2 mentioned |

### Lead Tiers

- 🔴 **HOT (0-3):** Major gaps everywhere. Highest priority lead.
- 🟠 **WARM (4-6):** Notable gaps. Good opportunity.
- 🟢 **COOL (7-10):** Reasonably prepared. Low priority.

## Input Format

### CSV File

```csv
name,domain,sector,employees
ForFarmers,forfarmers.nl,Animal Feed / Agriculture,2500
Cosun,cosun.nl,Food Production,4000
```

### JSON File

```json
{
  "companies": [
    {"name": "ForFarmers", "domain": "forfarmers.nl", "sector": "Agriculture", "employees": 2500}
  ]
}
```

## Output

### Markdown Report

A professional report including:
- Executive summary with lead distribution
- Ranking table (sorted by score, hottest first)
- Detailed per-company reports with findings
- **Sales approach recommendations** for each lead
- Methodology explanation

### JSON Data

Complete scan data in JSON format for integration with other systems.

## CLI Options

```
usage: scout.py [-h] [--input INPUT] [--domain DOMAIN] [--name NAME]
                [--sector SECTOR] [--employees EMPLOYEES] [--output OUTPUT]
                [--json JSON] [--timeout TIMEOUT] [--delay DELAY]
                [--workers WORKERS] [--verbose]

Input Options:
  --input, -i         Path to CSV or JSON file with companies to scan
  --domain, -d        Single domain to scan
  --name, -n          Company name (for single domain scan)
  --sector, -s        Company sector (for single domain scan)
  --employees, -e     Employee count estimate (for single domain scan)

Output Options:
  --output, -o        Path for markdown report (default: output/report.md)
  --json, -j          Path for JSON data output

Scan Options:
  --timeout, -t       Timeout for each scan operation in seconds (default: 8)
  --delay             Delay between companies in seconds (default: 1)
  --workers, -w       Max parallel workers (default: 1)
  --verbose, -v       Enable verbose output
```

## Examples

```bash
# Scan from CSV with verbose output
python scout.py --input data/sample_companies.csv --output output/report.md --verbose

# Scan with custom timeout and JSON output
python scout.py --input companies.csv --output report.md --json data.json --timeout 10

# Quick single-company test
python scout.py --domain nomios.nl --name "Nomios" --sector "Cybersecurity"
```

## NIS2 Context

NIS2 is an EU cybersecurity directive. The Dutch implementation (Cyberbeveiligingswet) takes effect Q2 2026.

### Who's Affected?

- **Essential Entities:** Energy, transport, banking, healthcare, water, digital infrastructure, government
- **Important Entities:** Food, manufacturing, chemicals, waste, postal, digital providers

### Size Thresholds

- Medium: 50+ employees OR €10M+ turnover
- Large: 250+ employees OR €50M+ turnover

### Why It Matters for Sales

- Board members are personally liable for compliance failures
- Fines up to €10M or 2% of global turnover
- Many companies are unaware or unprepared
- Supply chain requirements mean customers will audit suppliers

## Legal & Ethical Notes

✅ This tool uses **OSINT only** - no hacking or unauthorized access  
✅ All data is publicly available information  
✅ Rate-limited and polite to APIs  
✅ Identifiable User-Agent for transparency  

## Dependencies

- `dnspython` - DNS record lookups
- `requests` - HTTP requests
- `beautifulsoup4` - HTML parsing
- `lxml` - Fast HTML parser
- `python-whois` - Optional WHOIS lookups

## File Structure

```
lead-scout/
├── scout.py              # Main CLI entry point
├── scanners/
│   ├── dns_scanner.py    # SPF, DMARC, DKIM checks
│   ├── shodan_scanner.py # Shodan InternetDB API
│   ├── ssl_scanner.py    # TLS certificate validation
│   └── website_scanner.py # Website content analysis
├── scoring/
│   ├── scorer.py         # Lead scoring engine
│   └── nis2_sectors.py   # NIS2 sector mapping
├── reports/
│   └── markdown_report.py # Report generator
├── data/
│   ├── sample_companies.csv
│   └── nis2_sectors.json
├── output/               # Generated reports
├── requirements.txt
└── README.md
```

## Contributing

This tool is part of the Polderbase lead generation platform for Nomios.

---

*Built for Nomios - Finding companies that need cybersecurity before they know they need it.*
