"""
SENTRA CORE — Startup item detector.

Scans Windows registry Run keys and the Startup folder for persistence entries.
Safe no-op on non-Windows platforms.
"""

import logging
import os
import platform
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_SUSPICIOUS_EXTS = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".scr", ".com"}
_SUSPICIOUS_KEYWORDS = {"temp", "tmp", "appdata\\local\\temp", "suspicious", "update"}


def _score_path(path: str) -> Dict:
    lower = path.lower()
    suspicious = (
        any(ext in lower for ext in _SUSPICIOUS_EXTS)
        and any(kw in lower for kw in _SUSPICIOUS_KEYWORDS)
    )
    return {"suspicious": suspicious, "risk": "HIGH" if suspicious else "LOW"}


def _scan_registry() -> List[Dict]:
    items = []
    try:
        import winreg

        keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
        ]

        for hive, key_path, display in keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                idx = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, idx)
                        risk = _score_path(value)
                        items.append({
                            "name": name, "path": value, "location": display,
                            "type": "registry", **risk,
                        })
                        idx += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue
    except ImportError:
        pass
    except Exception as exc:
        logger.warning("Registry scan error: %s", exc)
    return items


def _scan_startup_folder() -> List[Dict]:
    items = []
    try:
        folder = os.path.expanduser(
            "~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        )
        if not os.path.isdir(folder):
            return items

        for fname in os.listdir(folder):
            fp = os.path.join(folder, fname)
            risk = _score_path(fp)
            items.append({"name": fname, "path": fp, "location": "Startup Folder", "type": "file", **risk})
    except Exception as exc:
        logger.warning("Startup folder scan error: %s", exc)
    return items


def scan_startup_items() -> List[Dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    return _scan_registry() + _scan_startup_folder()
