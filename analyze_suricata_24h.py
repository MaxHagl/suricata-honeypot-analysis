import sys
import os
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# ----------------------------
# CLI
# ----------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Analyze 24h Suricata CSV (flows/alerts) and output summary CSVs + PNG charts.")
    p.add_argument("csv", nargs="?", default="suricata_24h.csv", help="Path to the 24h CSV export from Kibana/ES.")
    p.add_argument("--tz", default="America/Chicago", help="Timezone for hourly charts (default: America/Chicago).")
    p.add_argument("--outdir", default="suricata_24h_report", help="Output directory for CSVs and PNGs.")
    return p.parse_args()

# ----------------------------
# IO + Cleaning
# ----------------------------
def load_csv(path):
    # Read as strings to avoid silent downcasting; we cast numerics later.
    df = pd.read_csv("/Users/maximilianhagl/cybersecurity/mini_clasifier/mini baseline clasifier even bigger.csv", dtype=str, keep_default_na=False)
    # Normalize common "missing" markers to NaN
    df.replace({"-": np.nan, "": np.nan, "None": np.nan}, inplace=True)
    # Trim quotes/whitespace
    for c in df.columns:
        if df[c].dtype == "object":
            df[c] = df[c].str.strip().str.strip('"')
    return df

def ensure_cols(df, cols):
    for c in cols:
        if c not in df.columns:
            df[c] = np.nan
    return df

def coerce_numeric(df, cols):
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df

# ----------------------------
# Time parsing
# ----------------------------
def parse_times(df, tz):
    # Find a timestamp column robustly
    def find_ts_col(df):
        for c in df.columns:
            cn = str(c).strip().strip('"').lstrip("\ufeff").lower()
            if cn in ("@timestamp", "timestamp", "time", "event_time", "date"):
                return c
        # heuristic probe
        for c in df.columns:
            s = df[c].astype(str).str.replace(" @ ", " ", regex=False)
            try:
                pd.to_datetime(s.head(15), errors="raise")
                return c
            except Exception:
                continue
        return None

    tscol = find_ts_col(df)
    if tscol is None:
        df["_ts_utc"] = pd.NaT
        df["_ts_ct"]  = pd.NaT
        return df

    def to_dt(s):
        if pd.isna(s):
            return pd.NaT
        s = str(s).replace(" @ ", " ")  # e.g., "Aug 30, 2025 @ 19:06:37.769"
        # Try parsing as UTC (handles ISO)
        try:
            return pd.to_datetime(s, utc=True, errors="raise")
        except Exception:
            # Parse naive then localize to UTC
            try:
                dt = pd.to_datetime(s, errors="raise")
                if getattr(dt, "tzinfo", None) is None:
                    return dt.tz_localize("UTC")
                return dt.tz_convert("UTC")
            except Exception:
                return pd.NaT

    df["_ts_utc"] = df[tscol].apply(to_dt)

    # Optional flow times
    for fc in ["flow.start", "flow.end"]:
        if fc in df.columns:
            df[fc] = df[fc].apply(to_dt)

    # CT view (fallback to UTC if tz problem)
    try:
        df["_ts_ct"] = df["_ts_utc"].dt.tz_convert(tz)
    except Exception:
        df["_ts_ct"] = df["_ts_utc"]
    return df

# ----------------------------
# Feature engineering
# ----------------------------
def derive_features(df):
    # Duration if both endpoints exist
    if "flow.start" in df.columns and "flow.end" in df.columns:
        df["duration_s"] = (df["flow.end"] - df["flow.start"]).dt.total_seconds()
    else:
        df["duration_s"] = np.nan

    # Bytes/packet ratios
    df = ensure_cols(df, ["flow.bytes_toserver", "flow.bytes_toclient", "flow.pkts_toserver", "flow.pkts_toclient"])
    df = coerce_numeric(df, ["flow.bytes_toserver", "flow.bytes_toclient", "flow.pkts_toserver", "flow.pkts_toclient"])
    df["bpp_srv"] = df["flow.bytes_toserver"] / df["flow.pkts_toserver"].replace(0, np.nan)
    df["bpp_cli"] = df["flow.bytes_toclient"] / df["flow.pkts_toclient"].replace(0, np.nan)

    # Normalize ports to numeric
    for pcol in ["src_port", "dest_port", "DestPort (dest_port)"]:
        if pcol in df.columns:
            df[pcol] = pd.to_numeric(df[pcol], errors="coerce")
    if "dest_port" not in df.columns and "DestPort (dest_port)" in df.columns:
        df["dest_port"] = df["DestPort (dest_port)"]

    # Ensure expected string cols exist
    for c in ["proto", "app_proto", "event_type", "tcp.state", "flow.state", "flow.reason", "geoip.country_code2", "geoip.as_org"]:
        if c not in df.columns:
            df[c] = np.nan

    return df

# ----------------------------
# Plots
# ----------------------------
def plot_hourly_counts(df, out_png):
    # Guard: only if we have valid timestamps
    if "_ts_ct" not in df.columns:
        print("Skipping hourly plot: _ts_ct missing")
        return
    dff = df.dropna(subset=["_ts_ct"]).copy()
    if dff.empty:
        print("Skipping hourly plot: no valid timestamps after parsing")
        return
    g = (dff.set_index("_ts_ct").resample("1H").size())
    if g.empty:
        print("Skipping hourly plot: resample produced no data")
        return
    plt.figure()
    g.plot(kind="line")
    plt.title("Events per hour (last 24h)")
    plt.xlabel("Hour")
    plt.ylabel("Events")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()

def plot_top_asn(df, out_png, topn=15):
    if "geoip.as_org" not in df.columns:
        return
    s = df["geoip.as_org"].dropna().value_counts().head(topn)
    if s.empty:
        return
    plt.figure()
    s.plot(kind="bar")
    plt.title(f"Top {topn} Attacker AS Orgs")
    plt.xlabel("AS Org")
    plt.ylabel("Events")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()

def plot_duration_hist(df, out_png):
    if "duration_s" not in df.columns:
        return
    vals = df["duration_s"].dropna()
    if vals.empty:
        return
    plt.figure()
    plt.hist(vals, bins=50)
    plt.title("Flow Duration (seconds)")
    plt.xlabel("seconds")
    plt.ylabel("count")
    plt.tight_layout()
    plt.savefig(out_png)
    plt.close()

# ----------------------------
# Main
# ----------------------------
def write_csv(df, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)

def main():
    args = parse_args()
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    df = load_csv(args.csv)
    df = parse_times(df, args.tz)
    df = derive_features(df)

    # Top source IPs
    agg = (df.groupby("src_ip", dropna=False)
             .agg(events=("src_ip", "size"),
                  first_seen=("_ts_utc", "min"),
                  last_seen=("_ts_utc", "max"),
                  bytes_to_srv=("flow.bytes_toserver", "sum"),
                  bytes_to_cli=("flow.bytes_toclient", "sum"))
             .reset_index()
             .sort_values("events", ascending=False))
    write_csv(agg.head(200), os.path.join(outdir, "top_ips.csv"))

    # Top AS orgs
    if "geoip.as_org" in df.columns:
        asn = (df.groupby("geoip.as_org", dropna=True)
                 .size()
                 .reset_index(name="events")
                 .sort_values("events", ascending=False))
        write_csv(asn.head(200), os.path.join(outdir, "top_as_orgs.csv"))

    # Hourly counts
    if "_ts_ct" in df.columns:
        hourly = (df.dropna(subset=["_ts_ct"])
                    .set_index("_ts_ct")["src_ip"]
                    .resample("1H").count()
                    .reset_index()
                    .rename(columns={"src_ip": "events"}))
        write_csv(hourly, os.path.join(outdir, "hourly_counts.csv"))

    # Alert categories / severities
    if "event_type" in df.columns:
        alerts = df[df["event_type"] == "alert"].copy()
        if not alerts.empty:
            cat = (alerts.groupby("alert.category", dropna=False)
                         .size().reset_index(name="events")
                         .sort_values("events", ascending=False))
            write_csv(cat, os.path.join(outdir, "alert_categories.csv"))
            sev = (alerts.groupby("alert.severity", dropna=False)
                          .size().reset_index(name="events")
                          .sort_values("events", ascending=False))
            write_csv(sev, os.path.join(outdir, "alert_severity.csv"))

    # Minimal feature table for ML
    minimal_cols = [c for c in [
        "_ts_utc","src_ip","src_port","dest_ip","dest_port","proto","app_proto",
        "flow.bytes_toserver","flow.bytes_toclient","flow.pkts_toserver","flow.pkts_toclient",
        "flow.state","flow.reason","tcp.state","tcp.syn","tcp.ack","tcp.rst",
        "duration_s","bpp_srv","bpp_cli","geoip.country_code2","geoip.asn","geoip.as_org",
        "event_type","alert.signature","alert.category","alert.severity"
    ] if c in df.columns]
    write_csv(df[minimal_cols], os.path.join(outdir, "flows_minimal.csv"))

    # Charts
    plot_hourly_counts(df, os.path.join(outdir, "timeline_hourly.png"))
    plot_top_asn(df, os.path.join(outdir, "top_as_orgs.png"))
    plot_duration_hist(df, os.path.join(outdir, "duration_hist.png"))

    print("Wrote outputs to:", os.path.abspath(outdir))
    for f in sorted(os.listdir(outdir)):
        print(" -", f)

if __name__ == "__main__":
    main()
