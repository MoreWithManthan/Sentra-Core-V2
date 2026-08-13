"""
AbuseIPDB IP-reputation client.

Free API key, 1,000 requests/day. Checked alongside VirusTotal and
URLhaus for every network connection lookup — a second, independent
opinion on remote-IP reputation rather than relying on one source.

Scope note: this only fires for network/IP checks (Quick Scan's network
findings, or a manual "Check Reputation" click in the Network tab) — it
is never called during a Deep or Custom scan, which only check files.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

import requests

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
_TIMEOUT = 15

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# ── Usage tracking — session-scoped, resets on backend restart ──────────────
_stats: Dict[str, Any] = {
    "requests_made": 0,
    "last_request_at": None,
    "last_result": None,
}


def get_stats() -> Dict[str, Any]:
    return dict(_stats)


def _record_request(summary: str) -> None:
    _stats["requests_made"] += 1
    _stats["last_request_at"] = datetime.now(timezone.utc).isoformat()
    _stats["last_result"] = summary


def has_api_key() -> bool:
    """Live check — reflects a key set at runtime via the Settings panel, not just .env."""
    return bool(ABUSEIPDB_API_KEY)


def set_api_key(key: str) -> None:
    """Update the active AbuseIPDB key at runtime and persist it across restarts."""
    global ABUSEIPDB_API_KEY
    ABUSEIPDB_API_KEY = (key or "").strip()
    try:
        from database import set_setting
        set_setting("abuseipdb_api_key", ABUSEIPDB_API_KEY)
    except Exception:
        logger.debug("Could not persist AbuseIPDB key to database", exc_info=True)


def load_persisted_key() -> None:
    """Restore a previously-saved key from the database if .env didn't provide one."""
    global ABUSEIPDB_API_KEY
    if ABUSEIPDB_API_KEY:
        return
    try:
        from database import get_setting
        persisted = get_setting("abuseipdb_api_key", "")
        if persisted:
            ABUSEIPDB_API_KEY = persisted
            logger.info("Restored AbuseIPDB key from a previous session")
    except Exception:
        logger.debug("Could not load persisted AbuseIPDB key", exc_info=True)


def check_ip(ip: str) -> Dict[str, Any]:
    """Check an IP's abuse reports and confidence score on AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        return {"status": "no_key", "message": "ABUSEIPDB_API_KEY not configured."}
    try:
        r = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=_TIMEOUT,
        )
        if r.status_code != 200:
            _record_request(f"HTTP {r.status_code}")
            return {"status": "error", "message": f"AbuseIPDB returned HTTP {r.status_code}"}

        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        verdict = "malicious" if score >= 75 else ("suspicious" if score >= 25 else "clean")
        _record_request(f"{ip} → {verdict} ({score}%)")

        return {
            "status": "success",
            "source": "abuseipdb",
            "ip": ip,
            "verdict": verdict,
            "abuse_confidence_score": score,
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "permalink": f"https://www.abuseipdb.com/check/{ip}",
        }
    except requests.exceptions.Timeout:
        _record_request("timeout")
        return {"status": "error", "message": "AbuseIPDB request timed out."}
    except requests.exceptions.RequestException as exc:
        _record_request(f"network error: {exc}")
        return {"status": "error", "message": str(exc)}
    except (ValueError, KeyError) as exc:
        _record_request(f"parse error: {exc}")
        return {"status": "error", "message": f"Unexpected AbuseIPDB response: {exc}"}
