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
# Historical risk profiling storage
RISK_HISTORY_FILE = "risk_history.json"


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


def load_risk_history() -> dict:
    """Load historical risk data per user."""
    if os.path.exists(RISK_HISTORY_FILE):
        try:
            with open(RISK_HISTORY_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_risk_history(risk_history: dict) -> None:
    """Save historical risk data per user."""
    with open(RISK_HISTORY_FILE, "w") as f:
        json.dump(risk_history, f, indent=2)


def update_risk_history(df: pd.DataFrame) -> pd.DataFrame:
    """Track risk history per user and flag repeat offenders."""
    df = df.copy()
    risk_history = load_risk_history()
    
    # Initialize user risk tracking if not exists
    if "user_id" not in df.columns:
        df["repeat_offender"] = False
        df["risk_history_count"] = 0
        return df
    
    from datetime import datetime
    
    # Update history for each user
    for user_id in df["user_id"].unique():
        user_rows = df[df["user_id"] == user_id]
        high_risk_count = len(user_rows[user_rows["risk"] == "HIGH"])
        medium_risk_count = len(user_rows[user_rows["risk"] == "MEDIUM"])
        anomaly_count = len(user_rows[user_rows["anomaly"] == -1])
        
        if user_id not in risk_history:
            risk_history[user_id] = {
                "total_high_risk": 0,
                "total_medium_risk": 0,
                "total_anomalies": 0,
                "first_seen": None,
                "last_seen": None
            }
        
        risk_history[user_id]["total_high_risk"] += high_risk_count
        risk_history[user_id]["total_medium_risk"] += medium_risk_count
        risk_history[user_id]["total_anomalies"] += anomaly_count
        risk_history[user_id]["last_seen"] = datetime.now().isoformat()
        if risk_history[user_id]["first_seen"] is None:
            risk_history[user_id]["first_seen"] = datetime.now().isoformat()
    
    # Mark repeat offenders (users with multiple high-risk events)
    df["repeat_offender"] = df["user_id"].apply(
        lambda uid: risk_history.get(uid, {}).get("total_high_risk", 0) > 1
    )
    df["risk_history_count"] = df["user_id"].apply(
        lambda uid: risk_history.get(uid, {}).get("total_high_risk", 0) + 
                    risk_history.get(uid, {}).get("total_medium_risk", 0)
    )
    
    save_risk_history(risk_history)
    return df

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
    
    # Generate user_id if missing (for historical tracking)
    if "user_id" not in df.columns:
        n = len(df)
        df["user_id"] = [f"user_{i % 20 + 1:03d}" for i in range(n)]
    
    # Generate user_role if missing
    if "user_role" not in df.columns:
        df["user_role"] = "employee"  # Default to employee
    
    # Generate attack_type if missing
    if "attack_type" not in df.columns:
        df["attack_type"] = "BENIGN"  # Default to benign

    # Geo columns
    if "country" not in df.columns:
        df["country"] = "Unknown"
    if "latitude" not in df.columns:
        df["latitude"] = 0.0
    if "longitude" not in df.columns:
        df["longitude"] = 0.0

    # Select columns for ML features (numeric only)
    feature_cols = ["hour", "failed_attempts", "foreign_ip"]
    # Keep all metadata columns
    metadata_cols = ["ip_address", "user_id", "user_role", "attack_type", "country", "latitude", "longitude"]
    df = df[feature_cols + metadata_cols]

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
    """Convert anomaly output to human-readable threat levels with role-based escalation."""
    df = df.copy()

    def classify(row):
        base_risk = "LOW"
        
        # Base risk from anomaly detection
        if row["anomaly"] == -1 and row["failed_attempts"] >= 3:
            base_risk = "HIGH"
        elif row["anomaly"] == -1:
            base_risk = "MEDIUM"
        
        # Role-based escalation: Admin accounts get higher risk
        if "user_role" in row and row["user_role"] == "admin":
            if base_risk == "MEDIUM":
                base_risk = "HIGH"  # Escalate admin MEDIUM to HIGH
            elif base_risk == "LOW" and row["anomaly"] == -1:
                base_risk = "MEDIUM"  # Escalate admin LOW anomaly to MEDIUM
        
        # Attack type-based escalation
        if "attack_type" in row:
            attack_type = row["attack_type"]
            if attack_type in ["BRUTE_FORCE", "CREDENTIAL_STUFFING"]:
                if base_risk == "MEDIUM":
                    base_risk = "HIGH"
            elif attack_type == "DATA_EXFILTRATION":
                # Data exfiltration is always high risk
                base_risk = "HIGH"
            elif attack_type == "SUSPICIOUS_LOCATION":
                if base_risk == "LOW":
                    base_risk = "MEDIUM"
        
        return base_risk

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
    df = update_risk_history(df)  # Add historical tracking
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

    # Attack type statistics
    attack_type_counts = {}
    if "attack_type" in df.columns:
        attack_type_counts = df["attack_type"].value_counts().to_dict()
    
    # Role-based statistics
    admin_high_risk = 0
    employee_high_risk = 0
    if "user_role" in df.columns:
        admin_high_risk = len(df[(df["user_role"] == "admin") & (df["risk"] == "HIGH")])
        employee_high_risk = len(df[(df["user_role"] == "employee") & (df["risk"] == "HIGH")])
    
    # Repeat offenders (users with multiple high-risk events)
    repeat_offenders = []
    if "repeat_offender" in df.columns and "user_id" in df.columns:
        repeat_offenders_df = df[df["repeat_offender"] == True]
        if len(repeat_offenders_df) > 0:
            repeat_offenders = repeat_offenders_df[["user_id", "user_role", "risk_history_count"]].drop_duplicates().to_dict(orient="records")
    
    # Historical risk data
    risk_history = load_risk_history()
    top_risky_users = []
    if risk_history:
        # Sort by total high risk events
        sorted_users = sorted(
            risk_history.items(),
            key=lambda x: x[1].get("total_high_risk", 0) + x[1].get("total_medium_risk", 0),
            reverse=True
        )[:10]  # Top 10
        top_risky_users = [
            {
                "user_id": uid,
                "total_high_risk": data.get("total_high_risk", 0),
                "total_medium_risk": data.get("total_medium_risk", 0),
                "total_anomalies": data.get("total_anomalies", 0)
            }
            for uid, data in sorted_users
        ]

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
        attack_type_counts=attack_type_counts,
        admin_high_risk=admin_high_risk,
        employee_high_risk=employee_high_risk,
        repeat_offenders=repeat_offenders,
        top_risky_users=top_risky_users,
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
