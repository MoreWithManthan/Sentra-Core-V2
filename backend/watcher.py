"""
SENTRA CORE — Watchdog filesystem auto-scanner.

Watches user-configured directories for new executable files and scans them
automatically, broadcasting results over WebSocket.
"""

import asyncio
import logging
import os
import platform
from typing import Any, Callable, List, Optional

logger = logging.getLogger(__name__)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _WATCHDOG = True
except ImportError:
    _WATCHDOG = False
    logger.info("watchdog not installed — auto-scan disabled. pip install watchdog")

_SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com"}

_observer: Optional[Any] = None
_broadcast_fn: Optional[Callable] = None
_loop: Optional[asyncio.AbstractEventLoop] = None


def set_broadcast(fn: Callable, loop: asyncio.AbstractEventLoop) -> None:
    global _broadcast_fn, _loop
    _broadcast_fn = fn
    _loop = loop


# Bug fix: this class definition used to sit unconditionally at module
# scope, inheriting directly from `FileSystemEventHandler` — a name that
# only exists if the `import watchdog` above actually succeeded. Python
# evaluates a class's base classes immediately when the `class` statement
# runs, regardless of any later `if not _WATCHDOG: return` guards in other
# functions, so importing this module with watchdog NOT installed crashed
# outright with `NameError: name 'FileSystemEventHandler' is not defined`
# — defeating the try/except above, which was clearly *intended* to let
# the app degrade gracefully without watchdog. Guarding the class
# definition itself behind `if _WATCHDOG:` is what actually delivers that
# graceful degradation; every call site that uses `_Handler` was already
# correctly guarded (start() returns early when `_WATCHDOG` is False), so
# nothing else needs to change.
if _WATCHDOG:
    class _Handler(FileSystemEventHandler):
        def on_created(self, event):
            if event.is_directory:
                return
            fp = event.src_path
            ext = os.path.splitext(fp)[1].lower()
            if ext not in _SUSPICIOUS_EXTENSIONS:
                return

            logger.info("Watcher detected new file: %s", fp)

            try:
                from engine.heuristics import analyze_file
                from engine.mitre_mapper import enrich_result
                result = analyze_file(fp)
                if result["score"] > 0:
                    threat = {
                        "file": fp,
                        "risk_score": result["score"],
                        "details": result["findings"],
                        "source": "auto_scan",
                    }
                    enrich_result(threat)
                    if _broadcast_fn and _loop:
                        asyncio.run_coroutine_threadsafe(
                            _broadcast_fn({
                                "type": "auto_threat",
                                "data": threat,
                            }),
                            _loop,
                        )
            except Exception as exc:
                logger.warning("Auto-scan error for %s: %s", fp, exc)
else:
    _Handler = None  # never instantiated — start() returns early without watchdog


def start(watch_dirs: List[str]) -> None:
    global _observer
    if not _WATCHDOG:
        return
    stop()

    valid_dirs = [d for d in watch_dirs if os.path.isdir(d)]
    if not valid_dirs:
        return

    _observer = Observer()
    handler = _Handler()
    for d in valid_dirs:
        _observer.schedule(handler, d, recursive=False)
    _observer.start()
    logger.info("Watchdog started — watching: %s", valid_dirs)


def stop() -> None:
    global _observer
    if _observer and _observer.is_alive():
        _observer.stop()
        _observer.join(timeout=3)
    _observer = None


def default_watch_dirs() -> List[str]:
    """Return platform-appropriate default directories to watch."""
    dirs = []
    if platform.system() == "Windows":
        for d in [
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Desktop"),
            os.environ.get("TEMP", ""),
        ]:
            if d and os.path.isdir(d):
                dirs.append(d)
    else:
        for d in [os.path.expanduser("~/Downloads"), "/tmp"]:
            if os.path.isdir(d):
                dirs.append(d)
    return dirs
