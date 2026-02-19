"""
AI-Based Authentication Threat Detection System
MVP Implementation
"""

import pandas as pd
from sklearn.ensemble import IsolationForest
from flask import Flask, render_template
import os

app = Flask(__name__)

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

    df = df[["hour", "failed_attempts", "foreign_ip"]]

    for col in df.columns:
        if not pd.api.types.is_numeric_dtype(df[col]):
            raise TypeError(f"Column '{col}' must be numeric.")

    if df.isnull().any().any():
        raise ValueError("Dataset contains missing values.")

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


# ──────────────────────────────────────────────
# PIPELINE RUNNER
# ──────────────────────────────────────────────

def run_pipeline(filepath: str) -> pd.DataFrame:
    df = ingest_data(filepath)
    df = process_features(df)
    df = detect_anomalies(df)
    df = assign_risk(df)
    return df


# ──────────────────────────────────────────────
# MODULE 5: Visualization Layer (Flask Routes)
# ──────────────────────────────────────────────

@app.route("/")
def dashboard():
    filepath = os.path.join(os.path.dirname(__file__), "auth_logs.csv")
    df = run_pipeline(filepath)

    # Summary stats
    total = len(df)
    high = len(df[df["risk"] == "HIGH"])
    medium = len(df[df["risk"] == "MEDIUM"])
    low = len(df[df["risk"] == "LOW"])
    anomaly_count = len(df[df["anomaly"] == -1])

    records = df.to_dict(orient="records")

    return render_template(
        "dashboard.html",
        records=records,
        total=total,
        high=high,
        medium=medium,
        low=low,
        anomaly_count=anomaly_count
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
