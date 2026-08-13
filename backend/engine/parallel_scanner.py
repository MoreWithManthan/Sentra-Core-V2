"""
SENTRA CORE — Parallel file scanner.

Uses ThreadPoolExecutor (4–8 workers) so file I/O and YARA matching
run concurrently without blocking the asyncio event loop.
"""

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="sentra-scan")


async def scan_files_streaming(
    files: List[str],
    scan_fn: Callable[[str], Optional[Dict[str, Any]]],
    on_progress: Optional[Callable[[int, int, str], Any]] = None,
) -> AsyncIterator[Dict[str, Any]]:
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    total = len(files)

    async def _worker(fp: str) -> None:
        try:
            result = await loop.run_in_executor(_executor, scan_fn, fp)
        except Exception as exc:
            logger.debug("Scan error %s: %s", fp, exc)
            result = None
        await queue.put((fp, result))

    tasks = [asyncio.create_task(_worker(fp)) for fp in files]

    for scanned in range(1, total + 1):
        fp, result = await queue.get()
        if on_progress:
            cb = on_progress(scanned, total, os.path.basename(fp))
            if asyncio.iscoroutine(cb):
                await cb
        if result is not None:
            yield result

    await asyncio.gather(*tasks, return_exceptions=True)
