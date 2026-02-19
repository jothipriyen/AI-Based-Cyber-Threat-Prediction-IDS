"""
AI-Based Authentication Threat Detection System
MVP Implementation
"""

import json
import os
import random
from pathlib import Path
from urllib.parse import quote, unquote

import pandas as pd
from flask import Flask, jsonify, redirect, render_template, request, url_for
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# Custom Jinja2 filter for URL path encoding
@app.template_filter('urlpath')
def urlpath_filter(s):
    """URL encode for path segments (handles dots in IP addresses)."""
    return quote(str(s), safe='')

# Blocked IPs storage file
BLOCKED_IPS_FILE = "blocked_ips.json"


def load_blocked_ips() -> set:
    """Load blocked IP addresses from JSON file."""
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, "r") as f:
                ips = json.load(f)
                # Normalize IPs: ensure they're strings and strip whitespace
                return {str(ip).strip() for ip in ips}
        except (json.JSONDecodeError, IOError):
            return set()
    return set()


def save_blocked_ips(blocked_ips: set) -> None:
    """Save blocked IP addresses to JSON file."""
    # Normalize IPs before saving (strip whitespace, ensure strings)
    normalized_ips = [str(ip).strip() for ip in blocked_ips]
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(normalized_ips, f, indent=2)

# ──────────────────────────────────────────────
# MODULE 1: Data Ingestion
# ──────────────────────────────────────────────

def ingest_data(filepath: str) -> pd.DataFrame:
    """Load and validate authentication log CSV."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    df = pd.read_csv(filepath)

    required_columns = {"hour", "failed_attempts", "foreign_ip"}
    if not required_columns.issubset(df.columns):
        raise ValueError(f"Missing required columns. Expected: {required_columns}")

    # Include ip_address if present, otherwise generate DETERMINISTIC placeholder
    # (Random IPs would change on every page load, so blocked IPs would never match!)
    if "ip_address" not in df.columns:
        n = len(df)
        idx = range(n)
        df["ip_address"] = [
            f"192.168.1.{(i % 250) + 1}" if df.loc[i, "foreign_ip"] == 0
            else f"203.0.{(i // 250) + 1}.{(i % 250) + 1}"
            for i in idx
        ]

    # Select columns for ML features (numeric only)
    feature_cols = ["hour", "failed_attempts", "foreign_ip"]
    df = df[feature_cols + ["ip_address"]]

    # Validate numeric columns
    for col in feature_cols:
        if not pd.api.types.is_numeric_dtype(df[col]):
            raise TypeError(f"Column '{col}' must be numeric.")

    if df[feature_cols].isnull().any().any():
        raise ValueError("Dataset contains missing values in feature columns.")

    return df


# ──────────────────────────────────────────────
# MODULE 2: Feature Processing
# ──────────────────────────────────────────────

def process_features(df: pd.DataFrame) -> pd.DataFrame:
    """Validate and prepare features for ML pipeline."""
    df = df.copy()

    # All features already numeric per spec — no encoding needed
    # Ensure correct dtypes
    df["hour"] = df["hour"].astype(int)
    df["failed_attempts"] = df["failed_attempts"].astype(int)
    df["foreign_ip"] = df["foreign_ip"].astype(int)
    
    # Ensure ip_address is a string (preserve it through pipeline)
    if "ip_address" in df.columns:
        df["ip_address"] = df["ip_address"].astype(str).str.strip()

    return df


# ──────────────────────────────────────────────
# MODULE 3: Anomaly Detection Engine
# ──────────────────────────────────────────────

def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """Run Isolation Forest on feature set."""
    df = df.copy()

    model = IsolationForest(
        contamination=0.2,
        random_state=42
    )

    features = df[["hour", "failed_attempts", "foreign_ip"]]
    df["anomaly"] = model.fit_predict(features)
    df["anomaly_score"] = model.decision_function(features)

    return df


# ──────────────────────────────────────────────
# MODULE 4: Threat Scoring Engine
# ──────────────────────────────────────────────

def assign_risk(df: pd.DataFrame) -> pd.DataFrame:
    """Convert anomaly output to human-readable threat levels."""
    df = df.copy()

    def classify(row):
        if row["anomaly"] == -1 and row["failed_attempts"] >= 3:
            return "HIGH"
        elif row["anomaly"] == -1:
            return "MEDIUM"
        else:
            return "LOW"

    df["risk"] = df.apply(classify, axis=1)
    return df


def assign_block_status(df: pd.DataFrame) -> pd.DataFrame:
    """Simulate intrusion prevention by marking HIGH risk events and manually blocked IPs."""
    df = df.copy()
    blocked_ips = load_blocked_ips()
    
    # Normalize blocked IPs: strip whitespace and convert to string
    blocked_ips_normalized = {str(ip).strip() for ip in blocked_ips}
    
    # Normalize IP addresses in dataframe: ensure they're strings and strip whitespace
    df["ip_address"] = df["ip_address"].astype(str).str.strip()
    
    # Auto-block HIGH risk events
    df["auto_blocked"] = df["risk"] == "HIGH"
    
    # Check if IP is manually blocked (using normalized comparison)
    df["manually_blocked"] = df["ip_address"].isin(blocked_ips_normalized)
    
    # Combined blocked status
    df["blocked"] = df["auto_blocked"] | df["manually_blocked"]
    
    return df


# ──────────────────────────────────────────────
# PIPELINE RUNNER
# ──────────────────────────────────────────────

def run_pipeline(filepath: str) -> pd.DataFrame:
    df = ingest_data(filepath)
    df = process_features(df)
    df = detect_anomalies(df)
    df = assign_risk(df)
    df = assign_block_status(df)
    return df


# ──────────────────────────────────────────────
# MODULE 5: Visualization Layer (Flask Routes)
# ──────────────────────────────────────────────

@app.route("/")
def dashboard():
    filepath = os.path.join(os.path.dirname(__file__), "auth_logs.csv")
    df = run_pipeline(filepath)

    # Load blocked IPs and ensure they're applied
    blocked_ips = load_blocked_ips()
    
    # Summary stats
    total = len(df)
    high = len(df[df["risk"] == "HIGH"])
    medium = len(df[df["risk"] == "MEDIUM"])
    low = len(df[df["risk"] == "LOW"])
    anomaly_count = len(df[df["anomaly"] == -1])
    blocked = len(df[df["blocked"]])
    
    # Count manually blocked: count unique IPs that are blocked and appear in data
    manually_blocked_in_data = df[df["manually_blocked"]]["ip_address"].unique()
    manually_blocked_count = len(manually_blocked_in_data)
    
    # Total manually blocked IPs (from storage, regardless of current data)
    total_manually_blocked_ips = len(blocked_ips)

    # Simple email alert simulation when HIGH risk events exist
    alert_triggered = high > 0
    if alert_triggered:
        print(
            f"[ALERT] {high} HIGH risk authentication events detected. "
            "Simulating email notification to security administrator..."
        )

    # Trend data: anomalies per hour (0–23)
    trend_series = (
        df.groupby("hour")["anomaly"]
        .apply(lambda s: int((s == -1).sum()))
        .sort_index()
    )
    trend_labels = trend_series.index.astype(int).tolist() if len(trend_series) > 0 else []
    trend_values = trend_series.values.tolist() if len(trend_series) > 0 else []

    records = df.to_dict(orient="records")

    return render_template(
        "dashboard.html",
        records=records,
        total=total,
        high=high,
        medium=medium,
        low=low,
        anomaly_count=anomaly_count,
        blocked=blocked,
        manually_blocked_count=manually_blocked_count,
        total_manually_blocked_ips=total_manually_blocked_ips,
        blocked_ips=list(blocked_ips),
        alert_triggered=alert_triggered,
        trend_labels=trend_labels,
        trend_values=trend_values,
    )


@app.route("/block/<path:ip>")
def block_ip(ip: str):
    """Block an IP address."""
    # Decode URL-encoded IP address and normalize
    ip = unquote(ip).strip()
    blocked_ips = load_blocked_ips()
    blocked_ips.add(ip)
    save_blocked_ips(blocked_ips)
    print(f"[IPS] IP '{ip}' has been manually blocked. Total blocked IPs: {len(blocked_ips)}")
    # Force redirect with cache prevention
    return redirect(url_for("dashboard") + "?_=" + str(os.urandom(4).hex()))


@app.route("/unblock/<path:ip>")
def unblock_ip(ip: str):
    """Unblock an IP address."""
    # Decode URL-encoded IP address and normalize
    ip = unquote(ip).strip()
    blocked_ips = load_blocked_ips()
    blocked_ips.discard(ip)
    save_blocked_ips(blocked_ips)
    print(f"[IPS] IP '{ip}' has been manually unblocked. Total blocked IPs: {len(blocked_ips)}")
    # Force redirect with cache prevention
    return redirect(url_for("dashboard") + "?_=" + str(os.urandom(4).hex()))


@app.route("/api/blocked_ips")
def api_blocked_ips():
    """API endpoint to get list of blocked IPs."""
    return jsonify({"blocked_ips": list(load_blocked_ips())})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
