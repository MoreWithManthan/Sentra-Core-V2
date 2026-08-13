"""
SENTRA CORE — Multi-source threat intelligence aggregator.

Waterfalls file-hash lookups across free/unlimited sources before
touching VirusTotal's rate-limited free tier, and merges IP reputation
across multiple providers instead of relying on a single source.

Hash lookup order:  MalwareBazaar (instant, unlimited, no key)
                     -> AlienVault OTX (instant, uncapped, free key)
                     -> VirusTotal (rate-limited, and the only one of the
                        three capable of a genuinely definitive "clean" —
                        it aggregates ~70 real AV engine scans; the other
                        two are detection databases, not scanners, so their
                        absence-of-evidence is "not_found", never "clean")
                     -> Digital signature check (Windows only) — if none of
                        the three hash databases have ever seen this exact
                        file, a valid Authenticode signature is the
                        strongest remaining trust signal, and the one that
                        actually resolves the common case of a legitimate
                        but obscure vendor binary nobody has submitted
                        anywhere before.

This is what makes "verify every suspicious file, not just the top 10"
practical — most known-bad and known-good files resolve on the first two
free, unlimited tiers and never touch VT's 4-requests-per-minute ceiling.

IP lookup: AbuseIPDB + URLhaus + VirusTotal are all checked and merged
(worst verdict wins), since reputation checks are cheap enough that a
waterfall isn't needed there. Scope note: IP/network checks only run
during Quick Scan (which includes network findings) or a manual "Check
Reputation" click in the Network tab — never during Deep/Custom scans,
which only examine files.
"""

import hashlib
import logging
import os
from typing import Any, Dict

from engine import abuseipdb, malwarebazaar, otx, signature_check, urlhaus
from engine.virustotal import check_ip_reputation as _vt_check_ip
from engine.virustotal import scan_file as _vt_scan_file

logger = logging.getLogger(__name__)

# Verdicts that mean "the hash-based waterfall reached no definitive
# answer" — worth trying a signature check before giving up entirely.
_INCONCLUSIVE_HASH_STATUSES = {"not_found", "error", "no_key"}


def _hash_file(path: str) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _cache_get(cache_key: str):
    try:
        from database import intel_get_cache
        return intel_get_cache(cache_key)
    except Exception:
        return None


def _cache_set(cache_key: str, result: Dict[str, Any]) -> None:
    try:
        from database import intel_set_cache
        intel_set_cache(cache_key, result)
    except Exception:
        pass


def check_file_reputation(file_path: str) -> Dict[str, Any]:
    """
    Waterfall hash lookup — MalwareBazaar -> OTX -> VirusTotal -> digital
    signature (Windows only, and only tried if the first three found
    nothing conclusive).

    Every suspicious finding from a scan is checked here with no top-N
    cutoff: safety takes priority over scan duration, and the two free,
    unlimited tiers absorb most of the volume before anything reaches
    VirusTotal's rate limit.
    """
    if not os.path.isfile(file_path):
        return {"status": "error", "message": f"File not found: {file_path}"}

    try:
        sha256 = _hash_file(file_path)
    except OSError as exc:
        return {"status": "error", "message": str(exc)}

    cache_key = f"multi:{sha256}"
    cached = _cache_get(cache_key)
    if cached:
        cached = dict(cached)
        cached["file_name"] = os.path.basename(file_path)
        cached["from_cache"] = True
        return cached

    mb_result = malwarebazaar.lookup_hash(sha256)
    if mb_result.get("status") == "success":
        mb_result["file_name"] = os.path.basename(file_path)
        _cache_set(cache_key, mb_result)
        return mb_result

    if otx.has_api_key():
        otx_result = otx.lookup_hash(sha256)
        if otx_result.get("status") == "success" and otx_result.get("verdict") == "malicious":
            otx_result["file_name"] = os.path.basename(file_path)
            _cache_set(cache_key, otx_result)
            return otx_result

    # Neither free tier returned a confirmed-malicious verdict — fall
    # through to VirusTotal for a definitive answer (including a
    # confirmed-clean verdict). vt_scan_file already caches its own
    # results in the legacy vt_cache table, so we don't double-cache here.
    vt_result = _vt_scan_file(file_path, upload_unknown=False)
    vt_result.setdefault("source", "virustotal")

    # If VT also came back inconclusive (never analyzed this exact hash,
    # a transient error, or no key configured), a hash-based answer simply
    # isn't available. Try a digital-signature check before giving up —
    # this is the actual fix for legitimate-but-obscure vendor binaries
    # that no hash database has ever seen.
    if vt_result.get("status") in _INCONCLUSIVE_HASH_STATUSES:
        sig_result = signature_check.check_signature(file_path)
        if sig_result.get("status") == "valid":
            return {
                "status": "success",
                "source": "signature",
                "verdict": "clean",
                "signer": sig_result.get("signer"),
                "file_name": os.path.basename(file_path),
                "message": f"Not found in any hash database, but validly signed by {sig_result.get('signer')}.",
            }
        # Checked hash databases AND signature, still nothing conclusive —
        # surface that plainly rather than silently returning VT's raw
        # not_found/error, which reads as "we don't know" without saying so.
        # Source is reset to "none" — leaving it as "virustotal" here would
        # misleadingly imply VT specifically confirmed something, when in
        # fact nothing did.
        vt_result["status"] = "inconclusive"
        vt_result["verdict"] = "unknown"
        vt_result["source"] = "none"
        vt_result["message"] = (
            "Not found in MalwareBazaar, OTX, or VirusTotal, and no valid digital "
            "signature — genuinely unreviewed, not confirmed either way."
        )

    return vt_result


def check_ip_reputation_multi(ip: str) -> Dict[str, Any]:
    """
    Combine AbuseIPDB, URLhaus, and VirusTotal's IP reputation into one
    verdict. Any source flagging the IP wins (worst-case merge) — the
    per-source breakdown is preserved so the UI can show which provider
    actually raised the flag.
    """
    results: Dict[str, Any] = {}

    if abuseipdb.has_api_key():
        results["abuseipdb"] = abuseipdb.check_ip(ip)

    results["urlhaus"] = urlhaus.check_host(ip)
    results["virustotal"] = _vt_check_ip(ip)

    verdict_rank = {"malicious": 2, "suspicious": 1, "clean": 0, "not_found": 0}
    worst_verdict = "clean"
    worst_rank = -1
    checked_sources = []

    for source, result in results.items():
        if result.get("status") == "success":
            checked_sources.append(source)
        verdict = result.get("verdict")
        rank = verdict_rank.get(verdict, -1)
        if rank > worst_rank:
            worst_rank = rank
            worst_verdict = verdict

    return {
        "status": "success" if checked_sources else "no_data",
        "ip": ip,
        "verdict": worst_verdict if checked_sources else "unknown",
        "sources": results,
        "checked_sources": checked_sources,
    }


def get_all_provider_stats() -> Dict[str, Any]:
    """
    Session-scoped request counts for every provider, so usage can be
    verified from inside the app instead of cross-checking each service's
    own external dashboard (which is often laggy, hard to interpret, or
    — for MalwareBazaar/URLhaus — doesn't exist in a per-key form at all).
    """
    return {
        "malwarebazaar": malwarebazaar.get_stats(),
        "otx": otx.get_stats(),
        "abuseipdb": abuseipdb.get_stats(),
        "urlhaus": urlhaus.get_stats(),
    }


def load_all_persisted_keys() -> None:
    """Called once at backend startup, alongside VirusTotal's own key restore."""
    otx.load_persisted_key()
    abuseipdb.load_persisted_key()
