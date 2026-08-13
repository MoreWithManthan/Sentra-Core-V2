"""FastAPI backend for SENTRA CORE."""

import asyncio
import functools
import logging
import os
import platform
import re
import stat
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import psutil
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

load_dotenv()

import database as db
import scheduler as sched
import watcher as wtch
from engine import abuseipdb as abuseipdb_engine
from engine import otx as otx_engine
from engine import threat_intel
from engine.defender import setup_sentra_exclusions
from engine.heuristics import analyze_file, calculate_system_shield_score, SUSPICIOUS_EXTENSIONS
from engine.mitre_mapper import enrich_result
from engine.models import (
    CleanupRequest, CleanupResult, CustomScanRequest, CustomScanResponse,
    DefenderExclusionRequest, DefenderExclusionResponse,
    DriveInfo, DrivesResponse, IntelMetadata, IPReputationRequest,
    ProcessInfo, ProviderKeyRequest, ReportRequest,
    ScanResult, ScheduleConfig, StartupVTCheckRequest, StatsEntry,
    ThreatIntelStatus, VTBatchRequest, VTKeyRequest, VTScanRequest,
    VTScanResult, VTUsageStatus, WatcherConfig,
)
from engine.network_monitor import get_connections
from engine.parallel_scanner import scan_files_streaming
from engine.startup_scanner import scan_startup_items
from engine.system_optimize import deep_optimize, quick_optimize
from engine.updater import get_rules_metadata, update_threat_database
from engine.virustotal import (
    batch_vt_scan, get_vt_stats, has_api_key,
    load_persisted_key, set_vt_api_key, test_connection as vt_test_connection,
    scan_file as vt_scan_file,
)
from engine.yara_scanner import scan_with_yara, invalidate_cache

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s — %(name)s — %(levelname)s — %(message)s",
)
logger = logging.getLogger(__name__)

_history: deque = deque(maxlen=30)

MIN_THREAT_SCORE = 25
# Raised from 10,000. A Deep/Custom scan target with more matching files
# than this cap used to be silently truncated to whichever files the walk
# reached first — in practice, the same subset every single run, since
# os.walk() traverses in a consistent order. See _collect_prioritized_files
# below for how the *selection* of which files count toward this cap is
# now decided, rather than just "whatever came first."
MAX_SCAN_FILES = 25000
# Safety backstop on the raw candidate-collection walk itself (before
# priority ranking/capping), so a pathological target — a network mount
# with millions of files, say — doesn't collect indefinitely. Set well
# above MAX_SCAN_FILES so there's genuinely more material to prioritize
# among than just the first MAX_SCAN_FILES files found.
WALK_CEILING = 150000
# Raised from 300 — Quick Scan was finishing too early because it capped
# out well before covering all of _get_quick_dirs() (which now also checks
# more locations; see _get_quick_dirs below).
QUICK_CAP = 2000
VT_CLEARED_SCORE_CAP = 5
# Applied when a file is checked against every hash-based source AND a
# digital-signature check, and NONE of them reach a definitive answer
# either way. This is deliberately *not* the same as VT_CLEARED_SCORE_CAP —
# "nobody has ever seen this file" is weaker evidence than "70 AV engines
# scanned it and found nothing," so the item stays visible for a human
# look instead of disappearing into the cleared/safe section.
INCONCLUSIVE_SCORE_CAP = 15

SCAN_EXCLUDED_DIRS = {
    "venv", ".venv", "env", "virtualenv", ".virtualenv",
    "node_modules", ".npm", ".yarn", ".pnpm-store",
    "__pycache__", "site-packages", "dist-packages", "dist-info",
    ".git", ".svn", ".hg",
    "dist", "build", ".next", ".nuxt", ".output",
    ".idea", ".vscode",
    "Scripts", "Include", "Lib", "bin", "lib", "lib64",
}


def _is_excluded(path: str) -> bool:
    return bool(set(path.replace("\\", "/").split("/")) & SCAN_EXCLUDED_DIRS)


def _is_critical(path: str) -> bool:
    return any(k in path.lower() for k in ("system32", "syswow64", "drivers", "config", "boot"))


def _get_quick_dirs() -> List[str]:
    """
    Directories checked by Quick Scan.

    Bug fix: this previously covered a very small set of locations and,
    combined with a low file cap, meant Quick Scan often finished almost
    instantly without actually covering common drop locations. Expanded to
    also check Desktop, Documents, the roaming temp folder, and the
    browser/Windows Update cache — plus a much higher QUICK_CAP (see
    module constants) and one extra level of directory depth in ws_scan.

    On Windows, %TEMP%/%TMP% can resolve to a different, near-empty folder
    when the process is elevated — a deliberate Windows security measure
    against temp-file privilege escalation. %USERPROFILE% stays tied to
    the logged-in account regardless of elevation, so it's used as the
    primary source; TEMP/TMP are kept as additional candidates rather than
    the only ones.
    """
    if platform.system() != "Windows":
        candidates = [
            "/tmp", "/var/tmp",
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/.cache"),
        ]
        return [d for d in candidates if os.path.isdir(d)]

    candidates: List[str] = []
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        candidates.append(os.path.join(user_profile, "AppData", "Local", "Temp"))
        candidates.append(os.path.join(user_profile, "Downloads"))
        candidates.append(os.path.join(user_profile, "Desktop"))
        candidates.append(os.path.join(user_profile, "Documents"))
        candidates.append(os.path.join(user_profile, "AppData", "Roaming", "Temp"))
        candidates.append(os.path.join(
            user_profile, "AppData", "Local", "Microsoft", "Windows", "INetCache"
        ))
    candidates.append(os.environ.get("TEMP", ""))
    candidates.append(os.environ.get("TMP", ""))
    candidates.append("C:\\Windows\\Temp")
    candidates.append("C:\\Windows\\Prefetch")
    candidates.append("C:\\$Recycle.Bin")

    seen, result = set(), []
    for d in candidates:
        if d and d not in seen and os.path.isdir(d):
            seen.add(d)
            result.append(d)
    return result


def _normalize_scan_path(path: str) -> str:
    """
    A bare drive letter like "D:" refers to the current directory on
    that drive in Windows, not its root — "D:\\" does. Normalize before
    walking so a drive-letter-only input behaves as expected.
    """
    path = path.strip().strip('"')
    if re.fullmatch(r"[A-Za-z]:", path):
        path += "\\"
    return os.path.abspath(path)


def _extract_executable_path(raw: str) -> str:
    """Strip quoting and trailing CLI arguments from a registry Run value."""
    raw = raw.strip()
    if raw.startswith('"'):
        end = raw.find('"', 1)
        if end > 0:
            return raw[1:end]
    match = re.match(r'^(.*?\.(exe|dll|bat|cmd|scr|ps1|vbs))(\s|$)', raw, re.IGNORECASE)
    return match.group(1) if match else raw.split(" ")[0]


def _walk_with_diagnostics(root: str, max_depth: int, stats: Dict[str, Any]):
    """
    Recursive walk shared by every scan type, bounded to max_depth
    levels. Every permission error and folder visited is counted in
    `stats` so a low-result scan can be explained rather than looking
    identical to "there's genuinely nothing here."
    """
    root_norm = os.path.normpath(root)
    root_depth = root_norm.count(os.sep)

    def _onerror(exc):
        stats["errors"] += 1
        if len(stats["error_samples"]) < 3:
            stats["error_samples"].append(str(exc))

    for dirpath, dirnames, filenames in os.walk(root_norm, onerror=_onerror):
        stats["dirs_walked"] += 1
        depth = dirpath.count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in SCAN_EXCLUDED_DIRS]
        for fname in filenames:
            stats["files_examined"] += 1
            yield os.path.join(dirpath, fname)


def _new_walk_stats() -> Dict[str, Any]:
    return {"dirs_walked": 0, "files_examined": 0, "errors": 0, "error_samples": []}


def _diagnose_low_results(stats: Dict[str, Any], location: str, found: int) -> str:
    if stats["errors"] > 0:
        return (
            f"Walked {stats['dirs_walked']} folders under {location} but couldn't access "
            f"{stats['errors']} of them (permission denied) — found {found} matching file(s). "
            f"Running the backend as Administrator usually resolves this."
        )
    if found == 0 and stats["files_examined"] > 0:
        return (
            f"Looked at {stats['files_examined']} files across {stats['dirs_walked']} folders "
            f"under {location} — none matched a checked extension."
        )
    if found == 0:
        return f"No files found under {location} — nothing to scan."
    return (
        f"Only found {found} matching file(s) across {stats['dirs_walked']} folders under "
        f"{location}. If that seems low, the folders checked may not be what you expected."
    )


# ---------------------------------------------------------------------------
# Priority-based file selection.
#
# Bug fix: a scan target with more matching files than the analysis cap
# (MAX_SCAN_FILES / QUICK_CAP) used to be silently truncated to whichever
# files the directory walk happened to reach first — in practice, the same
# subset every single run, since os.walk() traverses in a consistent order
# on a given filesystem. Entire subtrees could go permanently unscanned
# with no indication this had happened.
#
# Now: when a target has more candidates than the cap, every candidate is
# scored by _priority_score() and only the highest-priority ones are kept,
# so what gets left out (if anything does) is the least-interesting
# material, not an arbitrary function of directory-listing order — and the
# caller is told exactly how many files were left unscanned this run.
# ---------------------------------------------------------------------------

# Extension risk tiers for *ordering*, not for the heuristic risk score
# itself (that stays in heuristics.py, untouched). Weighted toward what's
# actually likely to matter: directly-executable/scripted files outrank
# passive .dll files, which are far more numerous on a typical system and,
# per this project's own scan history, the single biggest source of
# false-positive noise — no point spending analysis budget on ten thousand
# benign resource DLLs before a handful of .exe/.ps1/.vbs files get a look.
_PRIORITY_EXT_TIERS: List[Tuple[int, set]] = [
    (40, {".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".jse", ".wsf", ".hta", ".py", ".lnk", ".msi"}),
    (25, {".docm", ".xlsm", ".pptm"}),
    (15, {".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".jar"}),
    (10, {".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx"}),
]
_EXT_PRIORITY: Dict[str, int] = {ext: weight for weight, exts in _PRIORITY_EXT_TIERS for ext in exts}
_DEFAULT_EXT_PRIORITY = 5  # .dll and anything else not explicitly tiered above

_PRIORITY_HOT_SEGMENTS = {"temp", "tmp", "cache", "downloads", "desktop"}


def _is_hot_location(file_path: str) -> bool:
    """
    Broader than heuristics.py's own temp-dir check, which intentionally
    stays narrow for risk *scoring*. This is only used to *order* which
    files get analyzed first when a target has more matches than the
    analysis cap, so it's fine — and useful — to be more generous here
    about what counts as a common drop location.
    """
    parts = {p.lower() for p in file_path.replace("\\", "/").split("/")}
    return bool(parts & _PRIORITY_HOT_SEGMENTS)


def _priority_score(file_path: str, mtime: float, now: float) -> int:
    """Higher = scanned first when a target exceeds the analysis cap."""
    ext = os.path.splitext(file_path)[1].lower()
    score = _EXT_PRIORITY.get(ext, _DEFAULT_EXT_PRIORITY)

    if _is_hot_location(file_path):
        score += 20

    age_days = max(0.0, (now - mtime) / 86400)
    if age_days <= 7:
        score += 20
    elif age_days <= 30:
        score += 10
    elif age_days <= 180:
        score += 3

    return score


def _collect_prioritized_files(
    roots: List[str],
    max_depth: int,
    stats: Dict[str, Any],
    cap: int,
) -> Tuple[List[str], int]:
    """
    Walks every directory in `roots` (each up to max_depth), filters to
    SUSPICIOUS_EXTENSIONS, and returns up to `cap` files — the highest
    priority ones if there are more candidates than that (see
    _priority_score above), rather than just the first `cap` encountered.

    The walk itself still stops at WALK_CEILING candidates as a safety
    backstop against a pathological target, but that ceiling is set well
    above `cap` so there's real material to prioritize among.

    Returns (selected_files, total_candidates_found) — the caller uses the
    difference to tell the user how many lower-priority files were left
    unscanned this run.
    """
    scored: List[Tuple[int, str]] = []
    now = time.time()

    for root in roots:
        if len(scored) >= WALK_CEILING:
            break
        for fp in _walk_with_diagnostics(root, max_depth=max_depth, stats=stats):
            if _is_excluded(fp) or os.path.splitext(fp)[1].lower() not in SUSPICIOUS_EXTENSIONS:
                continue
            try:
                st = os.stat(fp)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            scored.append((_priority_score(fp, st.st_mtime, now), fp))
            if len(scored) >= WALK_CEILING:
                break

    total_found = len(scored)
    if total_found <= cap:
        return [fp for _, fp in scored], total_found

    scored.sort(key=lambda pair: -pair[0])
    return [fp for _, fp in scored[:cap]], total_found


def _scan_file(fp: str, skip_cleared: bool = True) -> Optional[Dict[str, Any]]:
    """
    Run the heuristic and YARA passes on one file. Only returns a result
    if the combined score clears MIN_THREAT_SCORE or an actionable YARA
    rule matched outright — a single weak signal is not enough to report
    a threat.

    New: cross-scan file memory (skip_cleared=True by default). Before
    doing any real work, checks whether this exact file (by path+mtime+
    size) already passed a previous scan clean — if so, it's skipped
    entirely rather than being re-heuristic-scanned and re-flagged from
    scratch every single time. A file that passes cleanly here is
    recorded so future scans can skip it too, until it actually changes.
    Pass skip_cleared=False (wired to the "Force full re-scan" toggle) to
    bypass this and check every file fresh regardless of history.

    Bug fixes:
      - Only YARA matches flagged `actionable` (i.e. not a purely
        informational rule per its metadata) count toward the score or
        get reported — this is what stops signed system files from being
        flagged purely because a low-severity/INFO rule happened to match.
      - Every result gets a unique `id`, independent of filename, so two
        different files that happen to share a name can never be
        conflated when a VirusTotal/threat-intel verdict comes back for
        one of them (see _verify_with_threat_intel).
    """
    try:
        stat = None
        if skip_cleared:
            try:
                stat = os.stat(fp)
                if db.get_cleared_file(fp, stat.st_mtime, stat.st_size):
                    return None  # unchanged since it was last verified clean
            except OSError:
                stat = None  # fall through to a normal scan either way

        h = analyze_file(fp)
        yr = scan_with_yara(fp)
        actionable_matches = [m for m in yr.get("matches", []) if m.get("actionable", True)]
        matches_names = [m.get("rule", "") for m in actionable_matches]
        details = h["findings"] + [f"YARA match: {r}" for r in matches_names]
        yara_score = min(len(actionable_matches) * 30, 60)
        score = min(h["score"] + yara_score, 100)

        if score >= MIN_THREAT_SCORE or actionable_matches:
            r = {
                "id": uuid.uuid4().hex,
                "file": fp, "type": "file", "vt_target": fp,
                "risk_score": score, "details": details,
                "vt_checked": False, "vt_verdict": None, "vt_source": None, "vt_cleared": False,
            }
            return enrich_result(r)

        # Passed cleanly — remember this so future scans can skip it
        # entirely until the file actually changes.
        try:
            if stat is None:
                stat = os.stat(fp)
            db.mark_file_cleared(fp, stat.st_mtime, stat.st_size, verdict="clean")
        except OSError:
            pass
    except Exception as exc:
        logger.debug("Scan error %s: %s", fp, exc)
    return None


def _network_findings() -> List[Dict[str, Any]]:
    findings = []
    for conn in get_connections():
        if not conn.get("suspicious"):
            continue
        findings.append({
            "id": uuid.uuid4().hex,
            "file": f"Network: {conn.get('process', 'unknown')} -> {conn.get('remote', '')}",
            "type": "network", "vt_target": conn.get("remote_ip", ""),
            "risk_score": 40,
            "details": [f"Connection to a commonly abused port ({conn.get('remote_port')})"],
            "mitre_id": "T1071", "mitre_name": "Application Layer Protocol",
            "mitre_tactic": "Command and Control",
            "vt_checked": False, "vt_verdict": None, "vt_source": None, "vt_cleared": False,
        })
    return findings


def _startup_findings() -> List[Dict[str, Any]]:
    findings = []
    for item in scan_startup_items():
        if not item.get("suspicious"):
            continue
        findings.append({
            "id": uuid.uuid4().hex,
            "file": f"Startup: {item.get('name', 'unknown')} ({item.get('location', '')})",
            "type": "startup", "vt_target": _extract_executable_path(item.get("path", "")),
            "risk_score": 45,
            "details": [f"Suspicious startup entry: {item.get('path', '')}"],
            "mitre_id": "T1547", "mitre_name": "Boot or Logon Autostart Execution",
            "mitre_tactic": "Persistence",
            "vt_checked": False, "vt_verdict": None, "vt_source": None, "vt_cleared": False,
        })
    return findings


async def _run_blocking(fn, *args):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, fn, *args)


async def _verify_with_threat_intel(results: List[Dict[str, Any]], ws: WebSocket) -> None:
    """
    Checks every flagged finding against the multi-source threat-intel
    waterfall (MalwareBazaar -> AlienVault OTX -> VirusTotal -> digital
    signature for files; AbuseIPDB + URLhaus + VirusTotal merged for
    network findings).

    Bug fixes:
      - No top-N cutoff. Every result in `results` is checked — safety
        over scan duration. This is only tractable because MalwareBazaar
        and OTX absorb most of the volume before VirusTotal's 4-req/min
        free tier ever comes into play.
      - Live updates are keyed by each result's unique `id`, not its
        filename, so two files sharing a name never inherit each other's
        verdict in the UI (see ScanResult.id and useWebSocket.js).
      - A verdict of "unknown" (checked everywhere, including a digital
        signature check, and still no definitive answer) gets its score
        reduced but is NOT marked cleared — it stays visible in the active
        list for a human look, rather than disappearing the way a genuine
        "clean" does.
      - A file that IS cleared here is also recorded in the cross-scan
        cleared-files cache, so it's skipped entirely on the next scan
        rather than having to re-walk this whole verification pipeline
        again for a file that hasn't changed.
    """
    await ws.send_json({"type": "vt_start", "count": len(results)})

    for r in results:
        target = r.get("vt_target", r["file"])
        if r.get("type") == "network":
            intel_result = await _run_blocking(threat_intel.check_ip_reputation_multi, target)
            source = "multi-source"
        else:
            intel_result = await _run_blocking(threat_intel.check_file_reputation, target)
            source = intel_result.get("source", "unknown")

        verdict = intel_result.get("verdict", intel_result.get("status", "unknown"))
        r["vt_checked"] = True
        r["vt_verdict"] = verdict
        r["vt_source"] = source

        if verdict == "clean":
            r["vt_cleared"] = True
            r["risk_score"] = min(r["risk_score"], VT_CLEARED_SCORE_CAP)
            if r.get("type") != "network":
                try:
                    stat = os.stat(r["file"])
                    db.mark_file_cleared(r["file"], stat.st_mtime, stat.st_size, verdict="clean")
                except OSError:
                    pass
        elif verdict == "unknown":
            # Checked hash databases, VirusTotal, and (on Windows) a
            # digital-signature check — nothing conclusive either way.
            # Weaker evidence than a real "clean", so reduce confidence
            # without hiding it.
            r["risk_score"] = min(r["risk_score"], INCONCLUSIVE_SCORE_CAP)

        await ws.send_json({
            "type": "vt_result",
            "id": r.get("id"),
            "file": os.path.basename(r["file"]),
            "verdict": verdict,
            "source": source,
            "cleared": r.get("vt_cleared", False),
            "detections": intel_result.get("detections", 0),
            "total_engines": intel_result.get("total_engines", 0),
        })


class WSManager:
    def __init__(self):
        self._sockets: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._sockets.append(ws)

    def disconnect(self, ws: WebSocket):
        try:
            self._sockets.remove(ws)
        except ValueError:
            pass

    async def broadcast(self, data: Dict):
        dead = []
        for ws in list(self._sockets):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


_ws_manager = WSManager()


async def _scheduled_scan():
    cfg = db.get_schedule_cfg()
    scan_type = cfg.get("scan_type", "quick")
    results: List[Dict] = []
    scanned_count = 0
    start = time.monotonic()

    if scan_type == "quick":
        for d in _get_quick_dirs():
            for fname in os.listdir(d):
                fp = os.path.join(d, fname)
                if os.path.isfile(fp) and os.path.splitext(fname)[1].lower() in SUSPICIOUS_EXTENSIONS:
                    scanned_count += 1
                    r = _scan_file(fp)
                    if r:
                        results.append(r)

    shield = calculate_system_shield_score(results)
    dur = time.monotonic() - start
    db.save_scan(scan_type, scanned_count, len(results), shield, dur, threat_list=results)
    await _ws_manager.broadcast({"type": "scheduled_scan_complete", "results": results, "shield_score": shield})


_deep_optimize_log: Dict[str, Any] = {"running": False, "output": "", "done": False, "error": ""}


async def _run_deep_optimize():
    global _deep_optimize_log
    _deep_optimize_log = {"running": True, "output": "", "done": False, "error": ""}
    await _ws_manager.broadcast({"type": "deep_optimize_started"})
    try:
        result = await _run_blocking(deep_optimize)
        _deep_optimize_log["output"] = result.get("output", "")
        if result.get("status") != "success":
            _deep_optimize_log["error"] = result.get("output", "Unknown error")
    except Exception as exc:
        _deep_optimize_log["error"] = str(exc)
    finally:
        _deep_optimize_log["running"] = False
        _deep_optimize_log["done"] = True
        await _ws_manager.broadcast({"type": "deep_optimize_complete", **_deep_optimize_log})


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SENTRA CORE starting up")
    db.init_db()
    load_persisted_key()
    threat_intel.load_all_persisted_keys()

    sch_cfg = db.get_schedule_cfg()
    sched.set_scan_callback(_scheduled_scan)
    sched.start()
    if sch_cfg.get("enabled"):
        sched.apply_config(True, sch_cfg["scan_type"], sch_cfg["frequency"],
                           sch_cfg["hour"], sch_cfg["minute"])

    loop = asyncio.get_event_loop()
    wtch.set_broadcast(_ws_manager.broadcast, loop)
    wch_cfg = db.get_watcher_cfg()
    if wch_cfg.get("enabled"):
        wtch.start(wch_cfg.get("watch_dirs") or wtch.default_watch_dirs())

    setup_sentra_exclusions()

    yield

    wtch.stop()
    sched.stop()
    logger.info("SENTRA CORE shutting down")


app = FastAPI(title="SENTRA CORE API", version="2.3.0", lifespan=lifespan)

app.add_middleware(CORSMiddleware,
    allow_origins=[
        os.getenv("FRONTEND_URL", "http://localhost:5173"),
        "http://localhost:5173", "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
    max_age=3600,
)


@app.exception_handler(Exception)
async def _err(req, exc):
    logger.error("Unhandled: %s", exc, exc_info=True)
    return JSONResponse(status_code=500, content={"status": "error", "message": str(exc)})


@app.get("/api/health")
async def health():
    return {"status": "operational", "version": "2.3.0",
            "timestamp": datetime.now().isoformat(), "os": platform.system()}


@app.websocket("/ws/telemetry")
async def ws_telemetry(ws: WebSocket):
    await _ws_manager.connect(ws)
    try:
        logical_cores = psutil.cpu_count(logical=True) or 1
        while True:
            agg: Dict[str, float] = {}
            for p in psutil.process_iter(["name", "cpu_percent"]):
                try:
                    n = p.info["name"] or "Unknown"
                    if n.lower() in ("system idle process", "idle"):
                        continue
                    agg[n] = agg.get(n, 0) + (p.info["cpu_percent"] or 0) / logical_cores
                except Exception:
                    pass
            procs = sorted(
                [{"name": n, "cpu_percent": round(c, 1)} for n, c in agg.items() if c > 0.1],
                key=lambda x: -x["cpu_percent"],
            )[:12]

            cpu = round(psutil.cpu_percent(interval=None), 1)
            mem = round(psutil.virtual_memory().percent, 1)
            ts = datetime.now().strftime("%H:%M:%S")

            entry = StatsEntry(time=ts, cpu=cpu, memory=mem)
            _history.append(entry)

            await ws.send_json({
                "type": "telemetry",
                "cpu": cpu,
                "memory": mem,
                "time": ts,
                "processes": procs,
                "history": [e.model_dump() for e in _history],
                "network": get_connections()[:20],
            })
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        _ws_manager.disconnect(ws)


@app.websocket("/ws/scan")
async def ws_scan(ws: WebSocket):
    await ws.accept()
    try:
        config = await ws.receive_json()
        scan_type = config.get("type", "quick")
        path = config.get("path", "")
        # Bug fix: verification no longer requires a VirusTotal key.
        # MalwareBazaar and URLhaus need no key at all, so "verify every
        # suspicious file" is meaningful even with zero keys configured.
        verify_vt = bool(config.get("verify_vt", True))
        # New: "Force full re-scan" toggle — bypasses the cross-scan
        # cleared-files cache so every file is checked fresh regardless of
        # history. Off by default, since the whole point of the cache is
        # to not redo work on files that haven't changed.
        force_rescan = bool(config.get("force_rescan", False))
        scan_fn = functools.partial(_scan_file, skip_cleared=not force_rescan)

        await ws.send_json({"type": "started", "scan_type": scan_type})

        files: List[str] = []
        target = ""
        walk_stats = _new_walk_stats()

        if scan_type != "quick" and platform.system() == "Windows":
            try:
                from engine.defender import _is_admin
                if not _is_admin():
                    await ws.send_json({
                        "type": "info",
                        "message": "Running without Administrator privileges — protected "
                                   "system folders will be skipped. Run the backend terminal "
                                   "as Administrator for a complete scan.",
                    })
            except Exception:
                pass

        if scan_type == "quick":
            quick_dirs = _get_quick_dirs()
            await ws.send_json({
                "type": "info",
                "message": "Checking: " + (", ".join(quick_dirs) if quick_dirs else "no valid folders found"),
            })
            files, total_candidates = _collect_prioritized_files(
                quick_dirs, max_depth=4, stats=walk_stats, cap=QUICK_CAP
            )
            if total_candidates > QUICK_CAP:
                await ws.send_json({
                    "type": "info",
                    "message": (
                        f"Found {total_candidates} matching files across the checked folders — "
                        f"scanning the {QUICK_CAP} highest-priority (recently modified, common "
                        f"drop locations, directly executable) first. "
                        f"{total_candidates - QUICK_CAP} lower-priority file(s) were not scanned this run."
                    ),
                })
        else:
            raw_target = path if path else ("C:\\" if platform.system() == "Windows" else "/")
            target = _normalize_scan_path(raw_target)

            if not os.path.isdir(target):
                await ws.send_json({
                    "type": "error",
                    "message": f"That folder doesn't exist or isn't accessible: {target}",
                })
                return

            try:
                # Bug fix: a target with more matching files than
                # MAX_SCAN_FILES used to be silently truncated to whichever
                # files the walk reached first — in practice, the same
                # subset every run. Now every candidate (up to the much
                # larger WALK_CEILING safety backstop) is ranked by
                # priority and the highest-value ones are kept; the user
                # is also told explicitly when this happens, below.
                files, total_candidates = _collect_prioritized_files(
                    [target], max_depth=64, stats=walk_stats, cap=MAX_SCAN_FILES
                )
            except Exception as exc:
                await ws.send_json({"type": "error", "message": f"Couldn't read that folder: {exc}"})
                return

            if total_candidates > MAX_SCAN_FILES:
                await ws.send_json({
                    "type": "info",
                    "message": (
                        f"Found {total_candidates} matching files under {target} — scanning the "
                        f"{MAX_SCAN_FILES} highest-priority (recently modified, common drop "
                        f"locations, directly executable) first. "
                        f"{total_candidates - MAX_SCAN_FILES} lower-priority file(s) were not "
                        f"scanned this run."
                    ),
                })

        total = len(files)
        await ws.send_json({"type": "progress", "scanned": 0, "total": total, "current_file": ""})

        low_threshold = 3 if scan_type == "quick" else 0
        if total <= low_threshold:
            location = target if scan_type != "quick" else (", ".join(_get_quick_dirs()) or "the usual locations")
            await ws.send_json({"type": "info", "message": _diagnose_low_results(walk_stats, location, total)})

        results: List[Dict] = []
        start = time.monotonic()

        async def on_progress(scanned: int, total: int, fname: str):
            await ws.send_json({"type": "progress", "scanned": scanned, "total": total, "current_file": fname})

        async for threat in scan_files_streaming(files, scan_fn, on_progress):
            results.append(threat)
            await ws.send_json({"type": "threat", "data": threat})

        if scan_type == "quick":
            for finding in _network_findings() + _startup_findings():
                results.append(finding)
                await ws.send_json({"type": "threat", "data": finding})

        if verify_vt and results:
            await _verify_with_threat_intel(results, ws)

        dur = time.monotonic() - start
        active_results = [r for r in results if not r.get("vt_cleared")]
        shield = calculate_system_shield_score(active_results)

        scan_id = db.save_scan(
            scan_type, total, len(active_results), shield, dur,
            path_scanned=(target if scan_type != "quick" else ""),
            threat_list=results,
        )

        await ws.send_json({
            "type": "complete",
            "scan_id": scan_id,
            "files_scanned": total,
            "threats_found": len(active_results),
            "shield_score": shield,
            "duration_sec": round(dur, 2),
            "timestamp": datetime.now().isoformat(),
        })
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.error("WS scan error: %s", exc)
        try:
            await ws.send_json({"type": "error", "message": "Something went wrong during the scan. Please try again."})
        except Exception:
            pass


@app.get("/api/system/stats-history", response_model=List[StatsEntry])
async def get_stats():
    entry = StatsEntry(
        time=datetime.now().strftime("%H:%M:%S"),
        cpu=round(psutil.cpu_percent(interval=0.1), 1),
        memory=round(psutil.virtual_memory().percent, 1),
    )
    _history.append(entry)
    return list(_history)


@app.get("/api/system/processes", response_model=List[ProcessInfo])
async def get_procs():
    agg: Dict[str, float] = {}
    cores = psutil.cpu_count(logical=True) or 1
    for p in psutil.process_iter(["name", "cpu_percent"]):
        try:
            n = p.info["name"] or "Unknown"
            if n.lower() in ("system idle process", "idle"):
                continue
            agg[n] = agg.get(n, 0) + (p.info["cpu_percent"] or 0) / cores
        except Exception:
            pass
    return sorted(
        [ProcessInfo(name=n, cpu_percent=round(c, 1)) for n, c in agg.items() if c > 0.1],
        key=lambda x: -x.cpu_percent,
    )[:12]


@app.get("/api/system/drives", response_model=DrivesResponse)
async def list_drives():
    drives = []
    for p in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(p.mountpoint)
            drives.append(DriveInfo(device=p.device, mountpoint=p.mountpoint,
                fstype=p.fstype, total_gb=round(u.total/1e9,2),
                used_gb=round(u.used/1e9,2), free_gb=round(u.free/1e9,2),
                percent_used=round(u.percent,1)))
        except (PermissionError, OSError):
            pass
    return DrivesResponse(status="success", drives=drives)


@app.get("/api/system/network")
async def get_network():
    return {"status": "success", "connections": get_connections()}


@app.get("/api/system/startup-items")
async def get_startup():
    return {"status": "success", "items": scan_startup_items()}


@app.post("/api/system/network/vt-check")
async def network_vt_check(req: IPReputationRequest):
    # Bug fix / provider addition: this used to be VirusTotal-only. Now
    # merges AbuseIPDB + URLhaus + VirusTotal into one verdict.
    return await _run_blocking(threat_intel.check_ip_reputation_multi, req.ip)


@app.post("/api/system/startup/vt-check")
async def startup_vt_check(req: StartupVTCheckRequest):
    if not os.path.isfile(req.path):
        raise HTTPException(status_code=404, detail=f"File not found: {req.path}")
    # Provider addition: waterfalls MalwareBazaar -> OTX -> VirusTotal
    # instead of calling VirusTotal directly.
    return await _run_blocking(threat_intel.check_file_reputation, req.path)


@app.get("/api/engine/vt-status", response_model=VTUsageStatus)
async def vt_status():
    return VTUsageStatus(**get_vt_stats())


@app.post("/api/engine/vt-key")
async def set_vt_key(req: VTKeyRequest):
    set_vt_api_key(req.api_key)
    return {"status": "success", "configured": bool(req.api_key.strip())}


@app.post("/api/engine/vt-test")
async def vt_test():
    return await _run_blocking(vt_test_connection)


# ── Multi-source threat intelligence — status & key management ──────────────

@app.get("/api/engine/intel-status", response_model=ThreatIntelStatus)
async def intel_status():
    # Bug fix: there was previously no way to verify from inside the app
    # whether MalwareBazaar/OTX/AbuseIPDB/URLhaus were actually being
    # called — the only option was cross-checking each provider's own
    # external dashboard, which is slow, inconsistent, and doesn't exist
    # in a useful form for MalwareBazaar/URLhaus at all. These per-provider
    # session counters make usage directly verifiable in Settings.
    stats = threat_intel.get_all_provider_stats()
    return ThreatIntelStatus(
        otx_configured=otx_engine.has_api_key(),
        abuseipdb_configured=abuseipdb_engine.has_api_key(),
        virustotal_configured=has_api_key(),
        malwarebazaar_usage=stats["malwarebazaar"],
        otx_usage=stats["otx"],
        abuseipdb_usage=stats["abuseipdb"],
        urlhaus_usage=stats["urlhaus"],
    )


@app.get("/api/engine/cleared-files-count")
async def cleared_files_count():
    """
    Number of files currently remembered as clean (cross-scan memory —
    see _scan_file's skip_cleared logic). Exposed so it's visible from
    Settings rather than being an invisible internal cache.
    """
    return {"count": db.get_cleared_files_count()}


@app.post("/api/engine/intel-key")
async def set_intel_key(req: ProviderKeyRequest):
    provider = req.provider.strip().lower()
    if provider == "otx":
        otx_engine.set_api_key(req.api_key)
    elif provider == "abuseipdb":
        abuseipdb_engine.set_api_key(req.api_key)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {req.provider}")
    return {"status": "success", "provider": provider, "configured": bool(req.api_key.strip())}


@app.post("/api/actions/cleanup", response_model=CleanupResult)
async def perform_cleanup(req: CleanupRequest, background_tasks: BackgroundTasks):
    result = await _run_blocking(quick_optimize)
    stats = CleanupResult(
        deleted_files=result["deleted_files"],
        errors=result["errors"],
        dns_reset=result["dns_reset"],
    )
    stats.message = f"Removed {stats.deleted_files} files. DNS: {'flushed' if stats.dns_reset else 'unchanged'}."

    if req.deep_clean:
        background_tasks.add_task(_run_deep_optimize)
        stats.message += " Deep optimization is running in the background."

    return stats


@app.post("/api/actions/system-repair")
async def system_repair(background_tasks: BackgroundTasks):
    if platform.system() != "Windows":
        return {"status": "error", "message": "System repair is Windows-only (SFC/DISM)."}
    background_tasks.add_task(_run_system_repair)
    return {"status": "started", "message": "Running SFC and DISM in the background — this can take several minutes."}


_repair_log: Dict = {"running": False, "sfc": "", "dism": "", "done": False, "error": ""}


async def _run_system_repair():
    global _repair_log
    _repair_log = {"running": True, "sfc": "", "dism": "", "done": False, "error": ""}
    await _ws_manager.broadcast({"type": "repair_started"})
    try:
        sfc = await asyncio.create_subprocess_exec(
            "sfc", "/scannow",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, _ = await sfc.communicate()
        _repair_log["sfc"] = out.decode(errors="ignore")
        await _ws_manager.broadcast({"type": "repair_sfc_done", "output": _repair_log["sfc"]})

        dism = await asyncio.create_subprocess_exec(
            "DISM", "/Online", "/Cleanup-Image", "/RestoreHealth",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, _ = await dism.communicate()
        _repair_log["dism"] = out.decode(errors="ignore")
        await _ws_manager.broadcast({"type": "repair_dism_done", "output": _repair_log["dism"]})
    except Exception as exc:
        _repair_log["error"] = str(exc)
        await _ws_manager.broadcast({"type": "repair_error", "message": str(exc)})
    finally:
        _repair_log["running"] = False
        _repair_log["done"] = True
        await _ws_manager.broadcast({"type": "repair_complete", **_repair_log})


@app.get("/api/actions/repair-status")
async def repair_status():
    return _repair_log


@app.get("/api/actions/deep-optimize-status")
async def deep_optimize_status():
    return _deep_optimize_log


@app.post("/api/engine/update")
async def trigger_update(background_tasks: BackgroundTasks):
    background_tasks.add_task(_do_update)
    return {
        "status": "started",
        "message": "Updating threat definitions in the background — this will finish in a moment.",
    }


async def _do_update():
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, update_threat_database)
        invalidate_cache()
        # New rules might catch something on a file that scanned clean
        # before this update — the cross-scan cleared-files cache needs to
        # be invalidated so everything gets at least one fresh look under
        # the new rule set, rather than being skipped forever based on a
        # verdict from before the update.
        if result.get("status") == "success":
            cleared_count = await loop.run_in_executor(None, db.clear_all_file_verdicts)
            if cleared_count:
                result["message"] = (
                    f"{result.get('message', '')} {cleared_count} previously-cleared "
                    f"file(s) will be re-checked on the next scan."
                ).strip()
        await _ws_manager.broadcast({"type": "intel_update_complete", **result})
    except Exception as exc:
        await _ws_manager.broadcast({
            "type": "intel_update_error",
            "message": f"Couldn't update threat definitions: {exc}",
        })


@app.get("/api/engine/intel/metadata", response_model=IntelMetadata)
async def intel_meta():
    return IntelMetadata(**get_rules_metadata())


@app.get("/api/engine/scan")
async def rest_quick_scan():
    results: List[Dict] = []
    scanned_count = 0
    start = time.monotonic()
    for d in _get_quick_dirs():
        for fname in os.listdir(d):
            fp = os.path.join(d, fname)
            if os.path.isfile(fp) and os.path.splitext(fname)[1].lower() in SUSPICIOUS_EXTENSIONS:
                scanned_count += 1
                r = _scan_file(fp)
                if r:
                    results.append(r)
    shield = calculate_system_shield_score(results)
    dur = time.monotonic() - start
    db.save_scan("quick", scanned_count, len(results), shield, dur, threat_list=results)
    return {"status": "complete", "scan_type": "quick", "shield_score": shield,
            "files_scanned": scanned_count, "results": results, "timestamp": datetime.now().isoformat()}


@app.post("/api/engine/custom-scan", response_model=CustomScanResponse)
async def rest_custom_scan(req: CustomScanRequest):
    target = _normalize_scan_path(req.path)
    if not os.path.isdir(target) and not os.path.isfile(target):
        raise HTTPException(status_code=404, detail=f"Path not found: {target}")

    allowed = set(req.include_extensions) if req.include_extensions else set(SUSPICIOUS_EXTENSIONS)
    files: List[str] = []
    if os.path.isfile(target):
        files.append(target)
    else:
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in SCAN_EXCLUDED_DIRS]
            for fname in filenames:
                fp = os.path.join(dirpath, fname)
                if not _is_excluded(fp) and os.path.splitext(fname)[1].lower() in allowed:
                    files.append(fp)
            if len(files) >= req.max_files:
                break

    truncated = len(files) > req.max_files
    files = files[:req.max_files]
    results: List[Dict] = []
    start = time.monotonic()
    for fp in files:
        r = _scan_file(fp)
        if r:
            results.append(r)
    shield = calculate_system_shield_score(results)
    dur = time.monotonic() - start
    db.save_scan("custom", len(files), len(results), shield, dur, path_scanned=target, threat_list=results)
    return CustomScanResponse(status="complete", scan_type="custom", path_scanned=target,
        files_scanned=len(files), threats_found=len(results), shield_score=shield,
        results=[ScanResult(**r) for r in results],
        timestamp=datetime.now().isoformat(), duration_sec=round(dur,2), truncated=truncated)


@app.post("/api/engine/vt-scan", response_model=VTScanResult)
async def vt_scan(req: VTScanRequest):
    if not os.path.isfile(req.file_path):
        raise HTTPException(status_code=404, detail=f"File not found: {req.file_path}")
    result = await _run_blocking(vt_scan_file, req.file_path, req.upload_unknown)
    return VTScanResult(**result)


@app.post("/api/engine/vt-batch")
async def vt_batch(req: VTBatchRequest):
    results = await _run_blocking(batch_vt_scan, req.file_paths, req.upload_unknown)
    return {"status": "complete", "files_scanned": len(results),
            "malicious": sum(1 for r in results if r.get("verdict") == "malicious"),
            "results": results, "timestamp": datetime.now().isoformat()}


@app.get("/api/history/scans")
async def scan_history(limit: int = 50):
    return {"status": "success", "scans": db.get_scan_history(limit)}


@app.get("/api/history/scans/{scan_id}/threats")
async def scan_threats(scan_id: int):
    return {"status": "success", "threats": db.get_threats_for_scan(scan_id)}


@app.get("/api/history/latest")
async def latest_scan():
    return db.get_latest_scan() or {"status": "no_scans"}


@app.post("/api/reports/generate")
async def generate_report(req: ReportRequest):
    from engine.report_generator import generate_pdf
    if req.scan_id:
        scans = db.get_scan_history(500)
        scan = next((s for s in scans if s["id"] == req.scan_id), None)
    else:
        scan = db.get_latest_scan()
    if not scan:
        raise HTTPException(status_code=404, detail="No scan data found")
    scan.setdefault("results", db.get_threats_for_scan(scan["id"]))
    pdf_bytes = await _run_blocking(generate_pdf, scan)
    fname = f"sentra-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.get("/api/schedule")
async def get_schedule():
    cfg = db.get_schedule_cfg()
    return {**cfg, "next_run": sched.get_next_run()}


@app.post("/api/schedule")
async def set_schedule(config: ScheduleConfig):
    db.save_schedule_cfg(config.enabled, config.scan_type, config.frequency,
                         config.hour, config.minute)
    sched.apply_config(config.enabled, config.scan_type, config.frequency,
                       config.hour, config.minute)
    return {"status": "success", "next_run": sched.get_next_run()}


@app.get("/api/watcher")
async def get_watcher():
    return db.get_watcher_cfg()


@app.post("/api/watcher")
async def set_watcher(config: WatcherConfig):
    dirs = config.watch_dirs or wtch.default_watch_dirs()
    db.save_watcher_cfg(config.enabled, dirs)
    if config.enabled:
        wtch.start(dirs)
    else:
        wtch.stop()
    return {"status": "success", "enabled": config.enabled, "watch_dirs": dirs}


@app.post("/api/system/defender/exclude", response_model=DefenderExclusionResponse)
async def defender_exclude(req: DefenderExclusionRequest):
    from engine.defender import add_exclusion
    return DefenderExclusionResponse(**add_exclusion(req.path))


@app.get("/api/system/defender/status")
async def defender_status():
    from engine.defender import _is_admin, _is_windows, get_exclusions
    return {"is_windows": _is_windows(), "is_admin": _is_admin(), **get_exclusions()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("API_HOST", "0.0.0.0"),
                port=int(os.getenv("API_PORT", 8000)),
                reload=os.getenv("RELOAD", "false").lower() == "true")
