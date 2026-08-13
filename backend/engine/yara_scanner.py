"""
YARA scanner wrapper for SENTRA CORE.

Works in two modes:
  1. yara-python installed → runs real YARA matching
  2. yara-python not installed → returns empty results gracefully
     (install with: pip install yara-python)
"""

import logging
import os
from typing import Any, Dict

logger = logging.getLogger(__name__)

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.info("yara-python not installed — YARA scanning disabled. "
                "Run: pip install yara-python")

RULES_PATH: str = os.getenv(
    "RULES_PATH",
    os.path.join(os.path.dirname(__file__), "rules", "active_threats.yar"),
)

_compiled_rules = None

# ---------------------------------------------------------------------------
# Match severity filtering (Bug fix: legitimate/signed files being flagged
# as suspicious). Curated rule packages like YARA-Forge tag every rule with
# meta.category, meta.score, and meta.importance. Not every match indicates
# malicious content — a purely informational rule (e.g. a leaked-certificate
# blocklist entry) matching a benign, signed binary shouldn't be scored the
# same as an actual malware-family detection. We flag each match as
# "actionable" or not; main.py's scoring only counts actionable matches.
# ---------------------------------------------------------------------------
_LOW_SIGNAL_CATEGORIES = {"info"}
_MIN_ACTIONABLE_SCORE = 40


def _is_actionable(match_meta: Dict[str, Any]) -> bool:
    category = str(match_meta.get("category", "")).strip().lower()
    if category in _LOW_SIGNAL_CATEGORIES:
        return False

    score = match_meta.get("score")
    if score is not None:
        try:
            if float(score) < _MIN_ACTIONABLE_SCORE:
                return False
        except (TypeError, ValueError):
            pass

    return True


def _load_rules():
    """Compile YARA rules from disk (cached after first load)."""
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    if not _YARA_AVAILABLE:
        return None

    if not os.path.isfile(RULES_PATH) or os.path.getsize(RULES_PATH) == 0:
        logger.warning("YARA rules file not found or empty: %s  "
                       "Run 'Update Intel' to download rules.", RULES_PATH)
        return None

    try:
        _compiled_rules = yara.compile(filepath=RULES_PATH)
        logger.info("YARA rules compiled from %s", RULES_PATH)
        return _compiled_rules
    except yara.SyntaxError as exc:
        logger.error("YARA syntax error: %s", exc)
        _compiled_rules = None
        return None


def invalidate_cache():
    """Call this after updating the rules file so they are reloaded."""
    global _compiled_rules
    _compiled_rules = None


def scan_with_yara(file_path: str) -> Dict[str, Any]:
    """
    Scan a single file with compiled YARA rules.

    Returns:
        {
            "available": bool,
            "matches":   [{"rule": str, "tags": [...], "meta": {...},
                           "actionable": bool}, ...],
            "error":     str | None,
        }

    `actionable` is False for matches on informational/low-severity rules
    (per rule metadata) — callers should only count actionable matches
    toward a threat score, while still surfacing all matches for context.
    """
    if not _YARA_AVAILABLE:
        return {"available": False, "matches": [], "error": "yara-python not installed"}

    rules = _load_rules()
    if rules is None:
        return {"available": True, "matches": [], "error": "Rules not loaded — run Update Intel"}

    if not os.path.isfile(file_path):
        return {"available": True, "matches": [], "error": f"File not found: {file_path}"}

    try:
        matches = rules.match(file_path, timeout=30)
        result_matches = []
        for m in matches:
            meta = dict(m.meta)
            result_matches.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "meta": meta,
                "actionable": _is_actionable(meta),
            })
        return {"available": True, "error": None, "matches": result_matches}
    except yara.TimeoutError:
        return {"available": True, "matches": [], "error": "Scan timed out (>30 s)"}
    except Exception as exc:
        logger.warning("YARA scan error for %s: %s", file_path, exc)
        return {"available": True, "matches": [], "error": str(exc)}
