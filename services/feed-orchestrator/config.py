"""
config.py — Environment variable configuration for feed-orchestrator.

All env vars are read at import time and exposed as module-level constants.
Security: API key values are NEVER logged. Only presence is logged via bool().
"""
import logging
import os

logger = logging.getLogger(__name__)

# ── OpenCTI connection ──────────────────────────────────────────────────────
OPENCTI_URL = os.environ.get("OPENCTI_URL", "http://opencti:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")

# ── Redis connection ────────────────────────────────────────────────────────
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")

# ── Feed API Keys (all optional — feeds are disabled if key is absent) ──────
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
MALWAREBAZAAR_AUTH_KEY = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "")
THREATFOX_AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY", "")

# ── Feed cadences (hours) ───────────────────────────────────────────────────
FEED_INTERVALS = {
    "urlhaus": 1,
    "malwarebazaar": 2,
    "threatfox": 2,
    "feodo": 4,
    "otx": 6,
}

# ── Per-source quality weights (D-09) ──────────────────────────────────────
# score = min(100, feed_count * 25 + recency_bonus + quality_weight)
QUALITY_WEIGHTS = {
    "feodo": 30,        # manually curated C2 blocklist — highest signal
    "otx": 25,          # analyst-curated pulses
    "threatfox": 20,    # community + analyst-reviewed
    "urlhaus": 15,      # automated with community validation
    "malwarebazaar": 15, # automated with community validation
}

# ── SIEM / Elasticsearch ────────────────────────────────────────────────────
ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")

# ── Alerting ────────────────────────────────────────────────────────────────
# Max reachable score with seen_in_feeds=1: feodo fresh = 65; otx fresh = 60.
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "55"))

# ── Key presence logging (never log key values) ─────────────────────────────
logger.info("OPENCTI_TOKEN configured: %s", bool(OPENCTI_TOKEN))
logger.info("OTX_API_KEY configured: %s", bool(OTX_API_KEY))
logger.info("MALWAREBAZAAR_AUTH_KEY configured: %s", bool(MALWAREBAZAAR_AUTH_KEY))
logger.info("THREATFOX_AUTH_KEY configured: %s", bool(THREATFOX_AUTH_KEY))
