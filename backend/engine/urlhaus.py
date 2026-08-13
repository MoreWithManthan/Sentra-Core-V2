"""
URLhaus (abuse.ch) domain/host reputation client.

No API key required, unlimited free tier. Used alongside AbuseIPDB and
VirusTotal to check network connections — a remote host associated with
malware distribution shows up here even if it isn't flagged elsewhere.

Scope note: this only fires for network/IP checks (Quick Scan's network
findings, or a manual "Check Reputation" click in the Network tab) — it
is never called during a Deep or Custom scan, which only check files.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

import requests

logger = logging.getLogger(__name__)

URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
_TIMEOUT = 15

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


def check_host(host: str) -> Dict[str, Any]:
    """
    Check a domain or IP against URLhaus's malicious-URL database.

    Returns:
        {"status": "success", "verdict": "malicious"|"suspicious"|"clean", ...}
        {"status": "not_found", ...}   — no known malicious URLs for this host
        {"status": "error", "message": ...}
    """
    if not host:
        return {"status": "error", "message": "No host provided."}
    try:
        r = requests.post(URLHAUS_HOST_URL, data={"host": host}, timeout=_TIMEOUT)
        if r.status_code != 200:
            _record_request(f"HTTP {r.status_code}")
            return {"status": "error", "message": f"URLhaus returned HTTP {r.status_code}"}

        data = r.json()
        query_status = data.get("query_status")

        if query_status == "no_results":
            _record_request(f"{host} → no results")
            return {"status": "not_found", "message": "No known malicious URLs for this host."}
        if query_status != "ok":
            _record_request(f"unexpected: {query_status}")
            return {"status": "error", "message": f"Unexpected response: {query_status}"}

        urls = data.get("urls") or []
        online = [u for u in urls if u.get("url_status") == "online"]
        verdict = "malicious" if online else ("suspicious" if urls else "clean")
        _record_request(f"{host} → {verdict}")

        return {
            "status": "success",
            "source": "urlhaus",
            "host": host,
            "verdict": verdict,
            "url_count": len(urls),
            "active_url_count": len(online),
            "permalink": f"https://urlhaus.abuse.ch/host/{host}/",
        }
    except requests.exceptions.Timeout:
        _record_request("timeout")
        return {"status": "error", "message": "URLhaus request timed out."}
    except requests.exceptions.RequestException as exc:
        _record_request(f"network error: {exc}")
        return {"status": "error", "message": str(exc)}
    except (ValueError, KeyError) as exc:
        _record_request(f"parse error: {exc}")
        return {"status": "error", "message": f"Unexpected URLhaus response: {exc}"}
