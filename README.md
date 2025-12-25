# VulnTrack 360 – Automated Vulnerability Dashboard

VulnTrack 360 is a Python-based vulnerability analytics tool that parses **Qualys** and **Nessus** exports, normalizes findings, correlates **CVEs** to **CIS Benchmarks**, calculates operational KPIs (MTTD/MTTR, SLA breach rate), and generates **Splunk-ready** JSON events for dashboards and executive reporting.

## Features
- **Ingest**: Qualys (CSV) and Nessus (CSV) exports
- **Normalize**: unified schema for assets, CVEs, severity, first_seen, last_seen, status, source
- **Correlate**: CVEs → CIS benchmark controls (via mapping file)
- **KPIs**:
  - Mean Time To Detect (**MTTD**)
  - Mean Time To Remediate (**MTTR**) for remediated findings
  - SLA/TTR breach rate by severity
  - Top recurring CVEs / most affected assets
- **Outputs**:
  - Splunk-ready JSON events (**HEC-friendly** JSON lines)
  - CSV summary report
  - KPI JSON

## Tech Stack
- Python 3.10+
- pandas
- python-dateutil

## Project Structure
```
vulntrack-360/
  data/sample/
  src/
    ingest/
    transform/
    output/
    main.py
  dashboards/
  tests/
  requirements.txt
  LICENSE
  README.md
```

## Quick Start
### 1) Install
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Run (using included sample data)
```bash
python src/main.py \
  --qualys data/sample/qualys_sample.csv \
  --nessus data/sample/nessus_sample.csv \
  --cve-cis-map data/sample/cve_to_cis_mapping.csv \
  --out-dir out/
```

### 3) Splunk (HEC)
The pipeline generates `out/splunk_events.jsonl` (one JSON object per line). You can send it to Splunk HEC:
```bash
curl -k https://<splunk-hec-host>:8088/services/collector \
  -H "Authorization: Splunk <TOKEN>" \
  -H "Content-Type: application/json" \
  --data-binary @out/splunk_events.jsonl
```

## Security Notes
- Do not commit real customer scan exports.
- Use redacted or synthetic data (like the samples in `data/sample/`).


