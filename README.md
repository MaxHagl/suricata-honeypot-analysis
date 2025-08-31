# Suricata Honeypot Analysis

📊 A 24-hour analysis of honeypot traffic collected with T-Pot Suricata.  
Includes CSV exports, Python analysis pipeline, and visualizations of attack patterns.

## Repo contents
- `analyze_suricata_24h.py` → Python script to parse Suricata CSVs
- `flows_minimal.csv` → clean dataset for ML
- `top_ips.csv`, `top_as_orgs.csv`, `hourly_counts.csv` → summary tables
- `timeline_hourly.png`, `top_as_orgs.png`, `duration_hist.png` → charts
- `report.md` → full 24h findings

## Quick start
```bash
python analyze_suricata_24h.py your_export.csv --tz America/Chicago --outdir report_out
