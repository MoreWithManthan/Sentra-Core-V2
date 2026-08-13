"""
Windows Defender exclusion helper for SENTRA CORE.

Requires: elevated (Administrator) privileges on Windows.
On non-Windows platforms this module is a no-op.
"""

import logging
import os
import platform
import subprocess
from typing import Dict, Any

logger = logging.getLogger(__name__)


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _is_admin() -> bool:
    if not _is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _powershell(command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
        capture_output=True,
        text=True,
        timeout=30,
    )


def add_exclusion(path: str) -> Dict[str, Any]:
    if not _is_windows():
        return {"status": "not_windows", "message": "Defender exclusion only applies on Windows."}

    if not _is_admin():
        return {
            "status": "no_admin",
            "message": (
                "Administrator privileges required to add Defender exclusions. "
                "Run the backend as Administrator, or add the exclusion manually:\n\n"
                f'  Add-MpPreference -ExclusionPath "{path}"\n\n'
                "Or open Windows Security → Virus & threat protection → "
                "Manage settings → Exclusions → Add an exclusion → Folder."
            ),
        }

    path = os.path.abspath(path)
    if not os.path.isdir(path):
        return {"status": "error", "message": f"Directory does not exist: {path}"}

    try:
        result = _powershell(f'Add-MpPreference -ExclusionPath "{path}"')
        if result.returncode == 0:
            logger.info("Defender exclusion added: %s", path)
            return {"status": "success", "message": f"Defender exclusion added for: {path}", "path": path}
        else:
            logger.error("Defender exclusion failed: %s", result.stderr)
            return {"status": "error", "message": f"PowerShell error: {result.stderr.strip()}"}
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "PowerShell command timed out."}
    except Exception as exc:
        logger.exception("Defender exclusion error")
        return {"status": "error", "message": str(exc)}


def get_exclusions() -> Dict[str, Any]:
    if not _is_windows():
        return {"status": "not_windows", "exclusions": []}

    if not _is_admin():
        return {"status": "no_admin", "exclusions": []}

    try:
        result = _powershell("(Get-MpPreference).ExclusionPath | ConvertTo-Json -Compress")
        if result.returncode == 0:
            import json
            raw = result.stdout.strip()
            exclusions = json.loads(raw) if raw else []
            if isinstance(exclusions, str):
                exclusions = [exclusions]
            return {"status": "success", "exclusions": exclusions}
        return {"status": "error", "exclusions": [], "message": result.stderr}
    except Exception as exc:
        return {"status": "error", "exclusions": [], "message": str(exc)}


def setup_sentra_exclusions() -> Dict[str, Any]:
    if not _is_windows():
        return {"status": "not_windows"}

    from engine.updater import RULES_PATH
    paths_to_exclude = [
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        os.path.dirname(RULES_PATH),
    ]

    results = []
    for path in paths_to_exclude:
        results.append(add_exclusion(path))

    success = sum(1 for r in results if r["status"] == "success")
    return {
        "status": "success" if success == len(paths_to_exclude) else "partial",
        "paths_excluded": success,
        "details": results,
    }
