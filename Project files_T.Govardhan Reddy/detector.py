import os
import re

import pandas as pd

HIGH_KEYWORDS = ["iex", "downloadstring", "encodedcommand"]
MEDIUM_KEYWORDS = ["bypass", "hidden", "executionpolicy"]
LOW_KEYWORDS = ["enc", "obfuscated", "powershell"]

BASE64_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b")
URL_PATTERN = re.compile(r"https?://[\w\-\./?&=%#]+", re.IGNORECASE)
OBFUSCATED_PATTERN = re.compile(
    r"(?i)(?:\\x[0-9a-f]{2}|%u[0-9a-f]{4}|-join\b|chr\(|\$\([^)]*\))"
)


def classify_severity(message: str) -> str:
    text = (message or "").lower()

    is_high = any(tok in text for tok in HIGH_KEYWORDS)
    is_medium = any(tok in text for tok in MEDIUM_KEYWORDS)
    is_low = any(tok in text for tok in LOW_KEYWORDS)

    if is_high:
        return "HIGH"
    if is_medium:
        return "MEDIUM"

    # enhanced detections for suspicious content
    if URL_PATTERN.search(text) or BASE64_PATTERN.search(message or "") or OBFUSCATED_PATTERN.search(message or ""):
        return "LOW"

    if is_low:
        return "LOW"

    return ""  # not suspicious


def risk_score(severity: str) -> int:
    if severity == "HIGH":
        return 95
    if severity == "MEDIUM":
        return 75
    if severity == "LOW":
        return 45
    return 0


def detect_suspicious(file_path: str) -> pd.DataFrame:
    """Read PowerShell logs from CSV and return suspicious entries with severity and risk score."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    df = pd.read_csv(file_path)
    if df.empty:
        return df

    if "Message" not in df.columns:
        raise ValueError("CSV must contain a 'Message' column")

    df["Message"] = df["Message"].astype(str)

    df["Severity"] = df["Message"].apply(classify_severity)
    df["RiskScore"] = df["Severity"].apply(risk_score)

    suspicious_df = df[df["Severity"].isin(["HIGH", "MEDIUM", "LOW"])].copy()

    return suspicious_df
