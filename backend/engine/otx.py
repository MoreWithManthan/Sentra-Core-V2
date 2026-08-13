"""
AlienVault OTX (Open Threat Exchange) hash/IoC lookup client.

Free API key, high/effectively-uncapped quota. Used as the second
waterfall tier for file-hash lookups — after MalwareBazaar, before
VirusTotal's rate-limited free tier.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

import requests

logger = logging.getLogger(__name__)

OTX_BASE = "https://otx.alienvault.com/api/v1"
_TIMEOUT = 15

OTX_API_KEY = os.getenv("OTX_API_KEY", "")

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
    return bool(OTX_API_KEY)


def set_api_key(key: str) -> None:
    """Update the active OTX key at runtime and persist it across restarts."""
    global OTX_API_KEY
    OTX_API_KEY = (key or "").strip()
    try:
        from database import set_setting
        set_setting("otx_api_key", OTX_API_KEY)
    except Exception:
        logger.debug("Could not persist OTX key to database", exc_info=True)


def load_persisted_key() -> None:
    """Restore a previously-saved key from the database if .env didn't provide one."""
    global OTX_API_KEY
    if OTX_API_KEY:
        return
    try:
        from database import get_setting
        persisted = get_setting("otx_api_key", "")
        if persisted:
            OTX_API_KEY = persisted
            logger.info("Restored AlienVault OTX key from a previous session")
    except Exception:
        logger.debug("Could not load persisted OTX key", exc_info=True)


def lookup_hash(sha256: str) -> Dict[str, Any]:
    """
    Check a file's SHA-256 against OTX's pulse database (threat intel
    shared by the security community).

    Bug fix: a hash with zero pulses is reported as "not_found", not
    "clean" — OTX has no detection engine of its own, so an absence of
    pulses means "no evidence either way," not a positive safety
    confirmation. Only VirusTotal (which aggregates real AV engine scans)
    can return a genuinely definitive "clean".
    """
    if not OTX_API_KEY:
        return {"status": "no_key", "message": "OTX_API_KEY not configured."}
    try:
        r = requests.get(
            f"{OTX_BASE}/indicators/file/{sha256}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            _record_request("not_found (404)")
            return {"status": "not_found", "message": "No OTX pulses reference this hash."}
        if r.status_code != 200:
            _record_request(f"HTTP {r.status_code}")
            return {"status": "error", "message": f"OTX returned HTTP {r.status_code}"}

        data = r.json()
        pulse_count = (data.get("pulse_info") or {}).get("count", 0)

        if pulse_count > 0:
            _record_request(f"{sha256[:12]}… → malicious ({pulse_count} pulses)")
            return {
                "status": "success",
                "source": "otx",
                "verdict": "malicious",
                "sha256": sha256,
                "pulse_count": pulse_count,
                "permalink": f"https://otx.alienvault.com/indicator/file/{sha256}",
            }

        _record_request(f"{sha256[:12]}… → no pulses")
        return {
            "status": "not_found",
            "source": "otx",
            "sha256": sha256,
            "pulse_count": 0,
            "message": "No OTX pulses reference this hash — no evidence either way.",
        }
    except requests.exceptions.Timeout:
        _record_request("timeout")
        return {"status": "error", "message": "OTX request timed out."}
    except requests.exceptions.RequestException as exc:
        _record_request(f"network error: {exc}")
        return {"status": "error", "message": str(exc)}
    except (ValueError, KeyError) as exc:
        _record_request(f"parse error: {exc}")
        return {"status": "error", "message": f"Unexpected OTX response: {exc}"}
