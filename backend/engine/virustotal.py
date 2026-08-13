"""VirusTotal API v3 client with local caching and usage tracking."""

import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

VT_BASE     = "https://www.virustotal.com/api/v3"
VT_API_KEY  = os.getenv("VT_API_KEY", "")
_TIMEOUT    = 30
_MIN_INTERVAL = 15.1
_last_req: float = 0.0

_stats: Dict[str, Any] = {
    "requests_made":   0,
    "cache_hits":      0,
    "last_request_at": None,
    "last_result":     None,
    "session_started": datetime.now(timezone.utc).isoformat(),
}


def get_vt_stats() -> Dict[str, Any]:
    cache_entries = 0
    try:
        from database import get_vt_cache_count
        cache_entries = get_vt_cache_count()
    except Exception:
        pass
    return {"configured": bool(VT_API_KEY), "cache_entries": cache_entries, **_stats}


def has_api_key() -> bool:
    return bool(VT_API_KEY)


def set_vt_api_key(key: str) -> None:
    global VT_API_KEY
    VT_API_KEY = (key or "").strip()
    try:
        from database import set_setting
        set_setting("vt_api_key", VT_API_KEY)
    except Exception:
        logger.debug("Could not persist VT key to database", exc_info=True)


def load_persisted_key() -> None:
    global VT_API_KEY
    if VT_API_KEY:
        return
    try:
        from database import get_setting
        persisted = get_setting("vt_api_key", "")
        if persisted:
            VT_API_KEY = persisted
            logger.info("Restored VirusTotal key from a previous session")
    except Exception:
        logger.debug("Could not load persisted VT key", exc_info=True)


def _record_request(summary: str) -> None:
    _stats["requests_made"] += 1
    _stats["last_request_at"] = datetime.now(timezone.utc).isoformat()
    _stats["last_result"] = summary


def _record_cache_hit() -> None:
    _stats["cache_hits"] += 1


def _rate_limit() -> None:
    global _last_req
    wait = _MIN_INTERVAL - (time.monotonic() - _last_req)
    if wait > 0:
        time.sleep(wait)
    _last_req = time.monotonic()


def _headers() -> Dict[str, str]:
    return {"x-apikey": VT_API_KEY, "Accept": "application/json"}


def _hash_file(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _lookup(file_hash: str) -> Dict:
    _rate_limit()
    r = requests.get(f"{VT_BASE}/files/{file_hash}", headers=_headers(), timeout=_TIMEOUT)
    if r.status_code == 200:  return r.json()
    if r.status_code == 404:  return {"_s": "not_found"}
    if r.status_code == 429:  return {"_s": "rate_limited"}
    return {"_s": f"http_{r.status_code}"}


def _upload(path: str) -> Optional[str]:
    _rate_limit()
    with open(path, "rb") as fh:
        r = requests.post(
            f"{VT_BASE}/files", headers=_headers(),
            files={"file": (os.path.basename(path), fh)}, timeout=60,
        )
    r.raise_for_status()
    return r.json().get("data", {}).get("id")


def _poll(analysis_id: str, max_wait: int = 60) -> Dict:
    deadline = time.monotonic() + max_wait
    url = f"{VT_BASE}/analyses/{analysis_id}"
    while time.monotonic() < deadline:
        _rate_limit()
        r = requests.get(url, headers=_headers(), timeout=_TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if data.get("data", {}).get("attributes", {}).get("status") == "completed":
                return data
        time.sleep(10)
    return {"_s": "timeout"}


def _parse(vt_data: Dict, file_hash: str) -> Dict:
    if "_s" in vt_data:
        msgs = {
            "not_found":    "Hash not in VirusTotal's database yet.",
            "rate_limited": "VirusTotal rate limit reached — try again shortly.",
            "timeout":      "Analysis is still in progress.",
        }
        return {"status": vt_data["_s"], "message": msgs.get(vt_data["_s"], "Unknown VT response."), "sha256": file_hash}

    attrs  = vt_data.get("data", {}).get("attributes", {})
    stats  = attrs.get("last_analysis_stats", {})
    mal    = stats.get("malicious", 0)
    sus    = stats.get("suspicious", 0)
    total  = sum(stats.values()) if stats else 0
    engines = [e for e, res in attrs.get("last_analysis_results", {}).items()
               if res.get("category") in ("malicious", "suspicious")][:20]

    verdict = "clean"
    if mal >= 3:              verdict = "malicious"
    elif mal > 0 or sus >= 2: verdict = "suspicious"

    return {
        "status": "success", "sha256": file_hash, "detections": mal + sus,
        "malicious": mal, "suspicious": sus, "total_engines": total,
        "verdict": verdict, "engines": engines,
        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
        "last_analysis_date": attrs.get("last_analysis_date"),
        "meaningful_name": attrs.get("meaningful_name", ""),
    }


def scan_file(file_path: str, upload_unknown: bool = False) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {"status": "no_key", "message": "VT_API_KEY not set in .env"}
    if not os.path.isfile(file_path):
        return {"status": "error", "message": f"File not found: {file_path}"}
    if os.path.getsize(file_path) > 32 * 1024 * 1024:
        return {"status": "error", "message": "File >32 MB — VT free tier limit"}

    try:
        file_hash = _hash_file(file_path)

        try:
            from database import vt_get_cache
            cached = vt_get_cache(file_hash)
            if cached:
                _record_cache_hit()
                cached["file_name"] = os.path.basename(file_path)
                cached["from_cache"] = True
                return cached
        except Exception:
            pass

        vt_data = _lookup(file_hash)
        result  = _parse(vt_data, file_hash)
        _record_request(f"{os.path.basename(file_path)} → {result.get('verdict', result.get('status'))}")

        if result.get("status") == "not_found" and upload_unknown:
            aid = _upload(file_path)
            if aid:
                vt_data = _poll(aid)
                result  = _parse(vt_data, file_hash)
                _record_request(f"{os.path.basename(file_path)} → {result.get('verdict', result.get('status'))}")

        result["file_name"]  = os.path.basename(file_path)
        result["from_cache"] = False

        if result.get("status") == "success":
            try:
                from database import vt_set_cache
                vt_set_cache(file_hash, result)
            except Exception:
                pass

        return result

    except requests.exceptions.Timeout:
        return {"status": "error", "message": "VirusTotal request timed out."}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "message": "Couldn't reach VirusTotal."}
    except Exception as exc:
        logger.exception("VT error for %s", file_path)
        return {"status": "error", "message": str(exc)}


def batch_vt_scan(file_paths: List[str], upload_unknown: bool = False) -> List[Dict]:
    return [{"file_path": p, **scan_file(p, upload_unknown)} for p in file_paths]


EICAR_TEST_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0"


def test_connection() -> Dict[str, Any]:
    if not VT_API_KEY:
        return {"status": "no_key", "message": "No API key configured yet."}
    try:
        vt_data = _lookup(EICAR_TEST_SHA256)
        result = _parse(vt_data, EICAR_TEST_SHA256)
        _record_request(f"Connection test → {result.get('verdict', result.get('status'))}")
        if result.get("status") == "success":
            result["message"] = (
                f"Connected — {result.get('malicious', 0)}/{result.get('total_engines', 0)} "
                f"engines flagged the standard test file, as expected. Your key works."
            )
        elif result.get("status") == "not_found":
            result["message"] = "Connected — the key works. (Test hash wasn't found, which is unusual but not a problem.)"
        return result
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def check_ip_reputation(ip: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {"status": "no_key", "message": "VT_API_KEY not set in .env"}
    try:
        _rate_limit()
        r = requests.get(f"{VT_BASE}/ip_addresses/{ip}", headers=_headers(), timeout=_TIMEOUT)
        if r.status_code == 200:
            data  = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
            verdict = "malicious" if mal >= 2 else "suspicious" if (mal or sus) else "clean"
            result = {
                "status": "success", "ip": ip, "verdict": verdict,
                "malicious": mal, "suspicious": sus,
                "total_engines": sum(stats.values()) if stats else 0,
                "country": attrs.get("country", ""),
                "as_owner": attrs.get("as_owner", ""),
                "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
            }
            _record_request(f"IP {ip} → {verdict}")
            return result
        if r.status_code == 404:
            _record_request(f"IP {ip} → no data on file")
            return {"status": "not_found", "ip": ip, "message": "No reputation data on file for this IP."}
        return {"status": "error", "message": f"VirusTotal returned HTTP {r.status_code}"}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
