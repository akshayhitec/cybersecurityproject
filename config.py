"""
config.py
---------
Central configuration for the Phishing Email Forensics Tool.
All tuneable constants live here so nothing is hard-coded elsewhere.
"""

import os

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER   = os.path.join(BASE_DIR, "uploads")
DB_PATH         = os.path.join(BASE_DIR, "database", "forensics.db")
REPORT_FOLDER   = os.path.join(BASE_DIR, "reports", "generated")

# ── Upload rules ───────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS  = {".eml"}          # Only .eml files accepted
MAX_CONTENT_LENGTH  = 5 * 1024 * 1024  # 5 MB hard limit

# ── Risk score thresholds ──────────────────────────────────────────────────
RISK_LOW_MAX    = 30   # 0–30  → Low
RISK_MEDIUM_MAX = 65   # 31–65 → Medium
                       # 66+   → High

# ── Flask secret key (change in production) ───────────────────────────────
SECRET_KEY = "phishing-forensics-dev-key-change-me"
