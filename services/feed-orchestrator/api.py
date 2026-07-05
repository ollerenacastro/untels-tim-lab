"""
api.py — FastAPI application for feed-orchestrator HTTP endpoints.

Endpoints:
  GET /feeds/status  — per-feed run history from Redis (DASH-01)
  GET /feeds/recent  — last N IOCs from ES tim-iocs index (MON-01)
  GET /health        — liveness probe

CORS: allow_origins includes https://localhost (dashboard :443) per T-06-01-01.
"""
import json
import logging
import re
import uuid

import requests
import stix2
from dateutil.parser import parse as parse_dt
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from redis import from_url as redis_from_url

from config import ALERT_THRESHOLD, ES_URL, REDIS_URL
from status import get_status

logger = logging.getLogger(__name__)

app = FastAPI(title="feed-orchestrator", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# One shared Redis client (connection pool) reused across requests — building a fresh
# client per request churned connections/FDs under the dashboard's 30s polling.
_redis = redis_from_url(REDIS_URL, decode_responses=True)

# Confirmed .name attribute values from each feed class (build_enabled_feeds order)
FEED_NAMES = ["urlhaus", "malwarebazaar", "threatfox", "feodo", "otx"]

# T-08-02: compiled once at module level; never raises on malformed/null input
_STIX_TYPE_RE = re.compile(r"^\[([a-z0-9-]+):")

_STIX_TYPE_MAP = {
    "ipv4-addr": "IPv4",
    "domain-name": "Domain",
    "url": "URL",
    "email-addr": "Email",
}


def _parse_type_from_pattern(pattern: str) -> str:
    """Map a STIX pattern string to a human-readable IOC type label.

    T-08-02 guard: never raises — malformed or empty patterns return 'Unknown'.
    """
    m = _STIX_TYPE_RE.match(pattern or "")
    if not m:
        return "Unknown"
    sco = m.group(1)
    if sco == "file":
        if "SHA-256" in pattern:
            return "SHA-256"
        if "SHA-1" in pattern:
            return "SHA-1"
        return "MD5"
    return _STIX_TYPE_MAP.get(sco, sco)


@app.get("/feeds/status")
def feeds_status():
    """Return per-feed status from Redis. Missing keys return safe defaults."""
    feeds = []
    for name in FEED_NAMES:
        h = get_status(_redis, name)
        feeds.append({
            "name": name,
            "last_run": h.get("last_run"),
            "ioc_count": int(h.get("ioc_count", 0)),
            "status": h.get("status", "never_run"),
        })
    return {"feeds": feeds}


@app.get("/feeds/alerts")
def feeds_alerts():
    """Return the 100 most recent high-confidence IOC alerts from Redis."""
    raw = _redis.lrange("tim:alerts", 0, -1)
    alerts = [json.loads(e) for e in raw]
    return {"threshold": ALERT_THRESHOLD, "alerts": list(reversed(alerts))}


@app.get("/feeds/recent")
def feeds_recent(limit: int = 200):
    """Return the most recent IOCs from ES tim-iocs index (MON-01).

    T-08-01: limit capped at 500 server-side — client cannot force a 99999-size ES request.
    """
    capped = min(limit, 500)
    try:
        resp = requests.get(
            f"{ES_URL}/tim-iocs/_search",
            json={"size": capped, "sort": [{"ts": {"order": "desc"}}]},
            timeout=10,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ES unavailable: {exc}")

    iocs = []
    for h in hits:
        src = h.get("_source", {})
        # Skip malformed docs rather than 500 the whole endpoint on one bad row.
        if "ts" not in src or "value" not in src:
            continue
        iocs.append({
            "ts": src["ts"],
            "value": src["value"],
            "type": _parse_type_from_pattern(src.get("pattern", "")),
            "feed": src.get("feed", "unknown"),
            "confidence": src.get("confidence", 0),
        })
    return {"iocs": iocs}


@app.get("/feeds/export/stix")
def export_stix():
    """Return a STIX 2.1 bundle of all high-confidence IOCs indexed in Elasticsearch."""
    try:
        resp = requests.get(
            f"{ES_URL}/tim-iocs/_search",
            json={"size": 1000, "sort": [{"ts": {"order": "desc"}}]},
            timeout=10,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ES unavailable: {exc}")

    indicators = []
    for hit in hits:
        src = hit.get("_source", {})
        try:
            indicators.append(stix2.Indicator(
                id=src.get("stix_id", f"indicator--{uuid.uuid4()}"),
                name=src["value"],
                pattern=src["pattern"],
                pattern_type="stix",
                valid_from=parse_dt(src["ts"]),
                confidence=src["confidence"],
                labels=[src.get("feed", "unknown")],
            ))
        except Exception as exc:  # skip one bad doc, don't 500 the whole bundle
            logger.warning("[export] skipping malformed IOC doc: %s", exc)
            continue

    bundle = stix2.Bundle(*indicators, allow_custom=True)
    return Response(content=bundle.serialize(), media_type="application/stix+json")


@app.get("/health")
def health():
    return {"status": "ok"}
