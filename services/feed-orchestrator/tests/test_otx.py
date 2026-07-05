"""
test_otx.py — RED phase tests for OTXFeed (FEED-03).

These tests will raise ImportError until feeds/otx.py is implemented (Wave 3, Plan 06).
That is expected and correct.

OTX indicator type strings (per RESEARCH.md Assumption A6 — must be verified in Wave 0):
  "IPv4", "domain", "URL", "FileHash-MD5", "FileHash-SHA256", "FileHash-SHA1"
All other types (email, mutex, CVE, hostname if separate, etc.) must be skipped.
"""
import pytest

# RED: This import will fail until Plan 06 creates feeds/otx.py
from feeds.otx import OTXFeed


def test_ipv4_type_maps_to_ipv4_pattern(sample_otx_indicators):
    """FEED-03: OTX type 'IPv4' maps to [ipv4-addr:value = '...'] STIX pattern."""
    feed = OTXFeed()
    # sample_otx_indicators[0] has type="IPv4", indicator="1.2.3.4"
    ipv4_only = [sample_otx_indicators[0]]
    result = feed.normalize(ipv4_only)
    assert len(result) == 1
    assert result[0]["pattern"] == "[ipv4-addr:value = '1.2.3.4']"


def test_sha256_type_maps_to_sha256_pattern(sample_otx_indicators):
    """FEED-03: OTX type 'FileHash-SHA256' maps to file:hashes.'SHA-256' pattern (Pitfall 3)."""
    feed = OTXFeed()
    # sample_otx_indicators[4] has type="FileHash-SHA256"
    sha256_only = [sample_otx_indicators[4]]
    result = feed.normalize(sha256_only)
    assert len(result) == 1
    expected_pattern = (
        "[file:hashes.'SHA-256' = "
        "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
    )
    assert result[0]["pattern"] == expected_pattern


def test_sha1_type_maps_to_sha1_pattern():
    """FEED-03: OTX type 'FileHash-SHA1' maps to file:hashes.'SHA-1' pattern (Pitfall 3)."""
    feed = OTXFeed()
    sha1_indicator = [
        {
            "indicator": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "type": "FileHash-SHA1",
            "title": "SHA1 hash",
            "expiration": "",
            "is_active": 1,
            "_pulse_name": "Test Pulse",
        }
    ]
    result = feed.normalize(sha1_indicator)
    assert len(result) == 1
    assert result[0]["pattern"] == (
        "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']"
    )


def test_unknown_type_is_skipped():
    """FEED-03: Unknown OTX indicator types (e.g., 'email') produce no output."""
    feed = OTXFeed()
    email_indicator = [
        {
            "indicator": "attacker@evil.example.com",
            "type": "email",
            "title": "Attacker email",
            "expiration": "",
            "is_active": 1,
            "_pulse_name": "Test Pulse",
        }
    ]
    result = feed.normalize(email_indicator)
    assert result == []
