"""SENTRA CORE — APScheduler integration for automatic scans."""

import asyncio
import logging
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    _APScheduler = True
except ImportError:
    _APScheduler = False
    logger.info("apscheduler not installed — scheduled scans disabled. pip install apscheduler")

_scheduler: Optional[Any] = None
_scan_callback: Optional[Callable] = None   # set by main.py


def get_scheduler():
    global _scheduler
    if _APScheduler and _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


def set_scan_callback(cb: Callable) -> None:
    """Register the function to call when a scheduled scan fires."""
    global _scan_callback
    _scan_callback = cb


def start() -> None:
    s = get_scheduler()
    if s and not s.running:
        s.start()
        logger.info("APScheduler started")


def stop() -> None:
    s = get_scheduler()
    if s and s.running:
        s.shutdown(wait=False)


async def _run_scheduled_scan() -> None:
    if _scan_callback:
        logger.info("Running scheduled scan")
        try:
            await _scan_callback()
        except Exception as exc:
            logger.error("Scheduled scan error: %s", exc)


def apply_config(enabled: bool, scan_type: str, frequency: str, hour: int, minute: int) -> None:
    """Apply schedule config — replaces any existing auto_scan job."""
    s = get_scheduler()
    if not s:
        return

    try:
        s.remove_job("auto_scan")
    except Exception:
        pass

    if not enabled:
        logger.info("Scheduled scanning disabled")
        return

    freq_map = {
        "daily":   {"day_of_week": "*"},
        "weekly":  {"day_of_week": "mon"},
        "monthly": {"day": "1"},
    }
    kwargs = freq_map.get(frequency, {"day_of_week": "*"})

    s.add_job(
        _run_scheduled_scan,
        trigger=CronTrigger(hour=hour, minute=minute, **kwargs),
        id="auto_scan",
        replace_existing=True,
    )
    logger.info("Scheduled scan: %s at %02d:%02d (%s)", scan_type, hour, minute, frequency)


def get_next_run() -> Optional[str]:
    s = get_scheduler()
    if not s:
        return None
    try:
        job = s.get_job("auto_scan")
        if job and job.next_run_time:
            return job.next_run_time.isoformat()
    except Exception:
        pass
    return None
