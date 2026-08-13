"""Cross-platform system maintenance actions."""

import logging
import os
import platform
import shutil
import subprocess
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


def _remove_tree_contents(path: str) -> Tuple[int, int]:
    deleted, errors = 0, 0
    if not os.path.isdir(path):
        return deleted, errors
    for root, _, files in os.walk(path):
        for name in files:
            fp = os.path.join(root, name)
            try:
                os.remove(fp)
                deleted += 1
            except OSError:
                errors += 1
    return deleted, errors


def _flush_dns() -> bool:
    system = platform.system()
    try:
        if system == "Windows":
            r = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=15)
            return r.returncode == 0
        if system == "Darwin":
            subprocess.run(["dscacheutil", "-flushcache"], capture_output=True, timeout=15)
            r = subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, timeout=15)
            return r.returncode == 0
        for cmd in (["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"]):
            if shutil.which(cmd[0]):
                r = subprocess.run(cmd, capture_output=True, timeout=15)
                if r.returncode == 0:
                    return True
        return False
    except Exception:
        return False


def _linux_clean_package_cache() -> str:
    for manager, cmd in (
        ("apt", ["apt-get", "clean"]),
        ("dnf", ["dnf", "clean", "all"]),
        ("pacman", ["pacman", "-Sc", "--noconfirm"]),
    ):
        if shutil.which(manager):
            try:
                subprocess.run(cmd, capture_output=True, timeout=120)
                return manager
            except Exception:
                continue
    return ""


def quick_optimize() -> Dict[str, Any]:
    system = platform.system()
    temp_paths = (
        [os.environ.get("TEMP", ""), "C:\\Windows\\Temp", "C:\\Windows\\Prefetch"]
        if system == "Windows"
        else ["/tmp", "/var/tmp", os.path.expanduser("~/.cache")]
    )
    deleted = errors = 0
    for path in temp_paths:
        if path and os.path.isdir(path):
            d, e = _remove_tree_contents(path)
            deleted += d
            errors += e

    return {"deleted_files": deleted, "errors": errors, "dns_reset": _flush_dns()}


def _deep_optimize_windows() -> Dict[str, Any]:
    try:
        result = subprocess.run(
            ["DISM", "/Online", "/Cleanup-Image", "/StartComponentCleanup", "/ResetBase"],
            capture_output=True, text=True, timeout=900,
        )
        return {
            "status": "success" if result.returncode == 0 else "error",
            "output": (result.stdout or "") + (result.stderr or ""),
        }
    except Exception as exc:
        return {"status": "error", "output": str(exc)}


def _deep_optimize_macos() -> Dict[str, Any]:
    lines: List[str] = []
    try:
        result = subprocess.run(["purge"], capture_output=True, text=True, timeout=60)
        lines.append(result.stdout.strip() or "Inactive memory purged.")
    except Exception as exc:
        lines.append(f"Memory purge skipped: {exc}")

    deleted, errors = _remove_tree_contents(os.path.expanduser("~/Library/Caches"))
    lines.append(f"Cleared {deleted} cached files ({errors} skipped).")

    return {"status": "success", "output": "\n".join(lines)}


def _deep_optimize_linux() -> Dict[str, Any]:
    lines: List[str] = []
    manager = _linux_clean_package_cache()
    lines.append(f"Package cache cleaned ({manager})." if manager else "No supported package manager found.")

    if shutil.which("journalctl"):
        try:
            subprocess.run(["journalctl", "--vacuum-size=100M"], capture_output=True, timeout=60)
            lines.append("Journal logs trimmed to 100 MB.")
        except Exception as exc:
            lines.append(f"Journal trim failed: {exc}")

    return {"status": "success", "output": "\n".join(lines)}


def deep_optimize() -> Dict[str, Any]:
    system = platform.system()
    if system == "Windows":
        return _deep_optimize_windows()
    if system == "Darwin":
        return _deep_optimize_macos()
    return _deep_optimize_linux()
