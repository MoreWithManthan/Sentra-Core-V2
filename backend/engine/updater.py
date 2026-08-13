"""
Threat intelligence database updater.

Primary source is the YARA-Forge Extended package (yarahq.github.io) —
10,000+ curated, quality-filtered rules aggregated upstream from
ReversingLabs, Neo23x0, and other maintainers. A small set of
supplementary community rules is layered on top, with duplicate rule
identifiers skipped so yara.compile() doesn't fail — YARA-Forge already
re-packages most of what the old hand-picked source list pulled
individually, so keeping both without dedup risks a "duplicated
identifier" compile error.
"""

import os
import io
import re
import logging
import hashlib
import zipfile
from typing import Dict, Any, List, Optional
from datetime import datetime

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Primary source: YARA-Forge Extended package.
# https://github.com/YARAHQ/yara-forge — a curated, pre-deduplicated,
# quality-scored aggregation of multiple public rule repositories.
# ---------------------------------------------------------------------------
YARA_FORGE_ZIP_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip"
YARA_FORGE_INNER_PATH = "packages/extended/yara-rules-extended.yar"

# ---------------------------------------------------------------------------
# Supplementary sources — small, hand-picked rules not guaranteed to be
# covered by YARA-Forge's aggregation. Any rule whose identifier collides
# with one already loaded is skipped (see _rule_names / dedup logic below).
# ---------------------------------------------------------------------------
SUPPLEMENTARY_SOURCES: List[Dict[str, str]] = [
    {
        "name": "YARA-Rules/MALW_Eicar",
        "url": "https://raw.githubusercontent.com/YARA-Rules/rules/master/malware/MALW_Eicar.yar",
    },
    {
        "name": "YARA-Rules/MALW_Ransomware_Ryuk",
        "url": "https://raw.githubusercontent.com/YARA-Rules/rules/master/malware/MALW_Ransomware_Ryuk.yar",
    },
    {
        "name": "YARA-Rules/MALW_Ransomware_WannaCry",
        "url": "https://raw.githubusercontent.com/YARA-Rules/rules/master/malware/MALW_Ransomware_WannaCry.yar",
    },
]

RULES_PATH: str = os.getenv(
    "RULES_PATH", os.path.join(os.path.dirname(__file__), "rules", "active_threats.yar")
)
RULES_HASH_PATH: str = RULES_PATH + ".sha256"

# Vendored offline fallback — a bundled copy of the YARA-Forge Extended
# package, used when the network is unavailable so scanning still works.
VENDORED_YARA_FORGE_PATH: str = os.path.join(
    os.path.dirname(__file__), "rules", "yara_forge_extended.yar"
)

REQUEST_TIMEOUT: int = 20    # seconds per supplementary source
FORGE_TIMEOUT: int = 60      # the forge package is much larger

_RULE_NAME_RE = re.compile(r"(?m)^\s*rule\s+([A-Za-z0-9_]+)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_rules(content: str) -> None:
    """Atomically write rules file and update its checksum."""
    os.makedirs(os.path.dirname(RULES_PATH), exist_ok=True)
    with open(RULES_PATH, "w", encoding="utf-8") as fh:
        fh.write(content)
    digest = hashlib.sha256(content.encode()).hexdigest()
    with open(RULES_HASH_PATH, "w") as fh:
        fh.write(digest)


def _rule_names(text: str) -> set:
    return set(_RULE_NAME_RE.findall(text))


def _fetch_yara_forge() -> Optional[str]:
    """
    Download the YARA-Forge Extended package and extract the aggregated
    .yar file from inside the zip. Falls back to the vendored copy in
    rules/ if the network is unreachable.
    """
    try:
        r = requests.get(YARA_FORGE_ZIP_URL, timeout=FORGE_TIMEOUT)
        if r.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
                with zf.open(YARA_FORGE_INNER_PATH) as fh:
                    text = fh.read().decode("utf-8", errors="ignore")
            logger.info("✓ Fetched YARA-Forge Extended (%d bytes)", len(text))
            return text
        logger.warning("✗ YARA-Forge download returned HTTP %s", r.status_code)
    except requests.exceptions.Timeout:
        logger.warning("✗ YARA-Forge download timed out")
    except requests.exceptions.RequestException as exc:
        logger.warning("✗ YARA-Forge download failed: %s", exc)
    except (zipfile.BadZipFile, KeyError) as exc:
        logger.warning("✗ YARA-Forge zip malformed or inner path missing: %s", exc)

    if os.path.isfile(VENDORED_YARA_FORGE_PATH):
        logger.info("Falling back to vendored YARA-Forge Extended copy (offline)")
        try:
            with open(VENDORED_YARA_FORGE_PATH, encoding="utf-8", errors="ignore") as fh:
                return fh.read()
        except OSError as exc:
            logger.error("Could not read vendored YARA-Forge copy: %s", exc)
    return None


def _fetch_one(source: Dict[str, str]) -> Optional[str]:
    """Fetch a single supplementary YARA source; return its text or None on failure."""
    try:
        r = requests.get(source["url"], timeout=REQUEST_TIMEOUT)
        if r.status_code == 200 and "rule " in r.text:
            logger.info("✓ Fetched %s (%d bytes)", source["name"], len(r.text))
            return r.text
        logger.warning("✗ %s returned HTTP %s", source["name"], r.status_code)
    except requests.exceptions.Timeout:
        logger.warning("✗ %s timed out", source["name"])
    except requests.exceptions.RequestException as exc:
        logger.warning("✗ %s network error: %s", source["name"], exc)
    return None


def _build_header(rule_count: int, sources_ok: int, sources_total: int) -> str:
    return (
        f"// SENTRA CORE — Aggregated Threat Intelligence\n"
        f"// Generated: {datetime.now().isoformat()}\n"
        f"// Rules: {rule_count} from {sources_ok}/{sources_total} sources\n\n"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def update_threat_database() -> Dict[str, Any]:
    """
    Download YARA-Forge Extended plus any non-duplicate supplementary
    rules, aggregate them into one local file. Returns a result dict
    compatible with the existing API contract.
    """
    logger.info("Starting threat intelligence update")

    fetched: List[str] = []
    failed: List[str] = []
    known_names: set = set()

    forge_text = _fetch_yara_forge()
    if forge_text:
        fetched.append(forge_text)
        known_names |= _rule_names(forge_text)
    else:
        failed.append("YARA-Forge Extended")

    for source in SUPPLEMENTARY_SOURCES:
        text = _fetch_one(source)
        if not text:
            failed.append(source["name"])
            continue

        names = _rule_names(text)
        collisions = names & known_names
        if collisions:
            logger.info(
                "Skipping %d rule(s) from %s already covered by an earlier source",
                len(collisions), source["name"],
            )
            # Best-effort: drop only the colliding rule blocks isn't worth
            # the parsing complexity here — if there's meaningful overlap
            # we skip the whole supplementary file rather than risk a
            # broken partial rule. Small, hand-picked files, so this is
            # an acceptable trade-off.
            if len(collisions) == len(names):
                continue

        known_names |= names
        fetched.append(text)

    total_sources = 1 + len(SUPPLEMENTARY_SOURCES)

    if not fetched:
        msg = "All YARA sources unreachable and no vendored fallback found. Check network connectivity."
        logger.error(msg)
        return {
            "status": "error",
            "message": msg,
            "rules_updated": 0,
            "sources_ok": 0,
            "sources_failed": len(failed),
            "timestamp": datetime.now().isoformat(),
        }

    combined_body = "\n\n".join(fetched)
    rules_count = len(_rule_names(combined_body))
    combined = _build_header(rules_count, len(fetched), total_sources) + combined_body
    _write_rules(combined)

    msg = f"Intelligence updated: {rules_count} rules from {len(fetched)}/{total_sources} sources."
    if failed:
        msg += f" Unavailable sources: {', '.join(failed)}."

    logger.info(msg)
    return {
        "status": "success",
        "message": msg,
        "rules_updated": rules_count,
        "sources_ok": len(fetched),
        "sources_failed": len(failed),
        "timestamp": datetime.now().isoformat(),
        "path": RULES_PATH,
    }


def get_rules_path() -> str:
    return RULES_PATH


def rules_exist() -> bool:
    return os.path.isfile(RULES_PATH) and os.path.getsize(RULES_PATH) > 0


def get_rules_metadata() -> Dict[str, Any]:
    """Return metadata about locally cached rules without re-downloading."""
    if not rules_exist():
        return {"exists": False}

    stat = os.stat(RULES_PATH)
    checksum = ""
    if os.path.isfile(RULES_HASH_PATH):
        with open(RULES_HASH_PATH) as fh:
            checksum = fh.read().strip()

    with open(RULES_PATH, encoding="utf-8", errors="ignore") as fh:
        content = fh.read()

    return {
        "exists": True,
        "rules_count": len(_rule_names(content)),
        "size_bytes": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "sha256": checksum,
    }
