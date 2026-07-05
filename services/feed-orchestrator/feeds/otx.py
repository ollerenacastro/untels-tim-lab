"""
feeds/otx.py — AlienVault OTX feed parser (FEED-03).

Uses OTXv2 SDK to fetch pulses modified within the last interval_hours+1 hours.
The +1 hour window absorbs scheduler jitter (Pitfall 6 mitigation — never call
otx.getall() without modified_since; unbounded calls pull all historical pulses).

Disabled gracefully when OTX_API_KEY is absent (D-07 pattern).

Security: OTX_API_KEY is passed directly to OTXv2() and never stored on self
or logged. Single quotes in indicator values are escaped before STIX interpolation
(T-02-06-02 mitigation).
"""
import logging
from datetime import datetime, timedelta, timezone

from OTXv2 import OTXv2

from config import FEED_INTERVALS, OTX_API_KEY, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

# Module-level constant — referenced directly by tests (test_otx.py imports OTX_TYPE_MAP).
# Maps OTX indicator type strings to (STIX pattern template, observable_type) tuples.
# Single quotes around SHA-256 and SHA-1 are required by STIX 2.1 (Pitfall 3).
OTX_TYPE_MAP: dict[str, tuple[str, str]] = {
    "IPv4":            ("[ipv4-addr:value = '{v}']",           "IPv4-Addr"),
    "domain":          ("[domain-name:value = '{v}']",         "Domain-Name"),
    "hostname":        ("[domain-name:value = '{v}']",         "Domain-Name"),
    "URL":             ("[url:value = '{v}']",                 "Url"),
    "FileHash-MD5":    ("[file:hashes.MD5 = '{v}']",          "StixFile"),
    "FileHash-SHA256": ("[file:hashes.'SHA-256' = '{v}']",    "StixFile"),
    "FileHash-SHA1":   ("[file:hashes.'SHA-1' = '{v}']",      "StixFile"),
}


class OTXFeed(BaseFeed):
    name = "otx"
    quality_weight = QUALITY_WEIGHTS["otx"]       # 25
    interval_hours = FEED_INTERVALS["otx"]         # 6

    def run(self, redis_client, pycti_client) -> None:
        if not OTX_API_KEY:
            logger.warning("[OTX] disabled: OTX_API_KEY not configured")
            redis_client.hset(
                f"tim:feed_status:{self.name}",
                mapping={"status": "disabled", "last_run": "", "ioc_count": 0, "error_msg": ""},
            )
            return
        super().run(redis_client, pycti_client)

    def fetch(self) -> list[dict]:
        otx = OTXv2(OTX_API_KEY, server="https://otx.alienvault.com")
        # Pitfall 6 mitigation: ALWAYS pass modified_since — never call getall() unbound.
        # Window = interval_hours + 1 to absorb scheduler jitter.
        since = datetime.now(timezone.utc) - timedelta(hours=self.interval_hours + 1)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
        pulses = otx.getall(modified_since=since_str)
        # Flatten pulses → indicators, tagging each with its pulse name.
        indicators: list[dict] = []
        for pulse in pulses:
            pulse_name = pulse.get("name", "")
            for ind in pulse.get("indicators", []):
                ind["_pulse_name"] = pulse_name
                indicators.append(ind)
        return indicators

    def _parse_indicator(self, ind: dict) -> dict | None:
        ind_type = ind.get("type", "")
        ind_value = ind.get("indicator", "").strip()
        if ind_type not in OTX_TYPE_MAP or not ind_value:
            return None
        pattern_tmpl, obs_type = OTX_TYPE_MAP[ind_type]
        # T-02-06-02: escape single quotes before interpolation into STIX pattern.
        val_safe = stix_escape(ind_value)
        pattern = pattern_tmpl.replace("{v}", val_safe)
        pulse_name = ind.get("_pulse_name", "")
        return {
            "name": f"OTX {ind_type} {ind_value[:64]}",
            "pattern": pattern,
            "observable_type": obs_type,
            "confidence": self.quality_weight,
            "labels": [pulse_name] if pulse_name else [],
            "source_name": "AlienVault OTX",
            # Use first-seen (created), not expiration: expiration is a FUTURE date, which
            # made compute_confidence see days_old=0 and inflate every OTX indicator's recency.
            "valid_from": ind.get("created", ""),
        }

    def normalize(self, raw: list[dict]) -> list[dict]:
        return [r for ind in raw if (r := self._parse_indicator(ind)) is not None]
