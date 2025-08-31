# Suricata Honeypot Report — 24h Snapshot

**Time window:** Aug 29, 2025 00:00 CT → Aug 30, 2025 00:00 CT  
**Total events:** 165,197  
**Peak hour:** Aug 29, 20:00 CT with ~14,636 events  

---

## Key Findings
- Attacks are dominated by a few ASNs:  
  - **NYBULA** (40k events)  
  - **AS-VULTR** (23k)  
  - **Global Connectivity Solutions LLP** (11.9k)  
- Top individual sources:  
  - `144.202.75.221` (22.8k events, bidirectional traffic → possible brute attempts)  
  - `196.251.66.157` & `196.251.66.164` (~20k events each, but 0 bytes → scan-only)  
  - `46.46.101.89` (9.5k, heavy bytes both ways)  
  - `208.67.108.93` (7.2k, TLS-related, high client bytes)  
- Flow durations are overwhelmingly **< 1s** → mostly scans, with a small tail of longer brute attempts.
- Alerts are low-value noise:  
  - *Generic Protocol Command Decode* (6,424 events, sev=3)  
  - Only **2 high-severity (sev=1)** alerts in the entire dataset.

---

## Visuals
![Timeline](timeline_hourly.png)  
*Events per hour — visible spike around 20:00 CT.*

![Top AS Orgs](top_as_orgs.png)  
*NYBULA and Vultr dominate traffic sources.*

![Flow Durations](duration_hist.png)  
*Most flows last under a second (scans).*

---

## Recommendations
- **Detection Rules**
  - Flag any IP with >100 SSH attempts in 10 minutes.  
  - Focus dashboards on severity 1–2 alerts to reduce noise.  
- **Defensive Actions**
  - Consider rate-limiting or blocking top /24s from NYBULA and Vultr.  
  - Track repeat offenders across multiple days for blacklist candidates.  
- **Research / Portfolio**
  - Expand to 72h or 1-week datasets to see persistence.  
  - Correlate with Heralding credential captures to link flows → username/password attempts.  
  - Document repeated ASNs as part of an “Attacker Infrastructure” section.

---


📂 suricata-24h-report/
 ├── analyze_suricata_24h.py   # analysis script
 ├── flows_minimal.csv         # clean feature set
 ├── top_ips.csv
 ├── top_as_orgs.csv
 ├── hourly_counts.csv
 ├── alert_categories.csv
 ├── alert_severity.csv
 ├── timeline_hourly.png
 ├── top_as_orgs.png
 ├── duration_hist.png
 └── report.md   # the report above
