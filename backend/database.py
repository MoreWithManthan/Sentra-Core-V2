"""SQLite persistence layer for scan history, VirusTotal caching, and app settings."""

import json
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "..", "sentra.db"))


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Safe to call multiple times."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type       TEXT    NOT NULL,
            path_scanned    TEXT,
            files_scanned   INTEGER DEFAULT 0,
            threats_found   INTEGER DEFAULT 0,
            shield_score    INTEGER DEFAULT 100,
            duration_sec    REAL    DEFAULT 0,
            timestamp       TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,
            file_path   TEXT    NOT NULL,
            risk_score  INTEGER DEFAULT 0,
            details     TEXT,
            mitre_id    TEXT,
            mitre_name  TEXT,
            timestamp   TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_threats_scan ON threats(scan_id);

        CREATE TABLE IF NOT EXISTS vt_cache (
            file_hash   TEXT PRIMARY KEY,
            result_json TEXT    NOT NULL,
            created_at  TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS schedule_cfg (
            id          INTEGER PRIMARY KEY,
            enabled     INTEGER DEFAULT 0,
            scan_type   TEXT    DEFAULT 'quick',
            frequency   TEXT    DEFAULT 'daily',
            hour        INTEGER DEFAULT 2,
            minute      INTEGER DEFAULT 0
        );
        INSERT OR IGNORE INTO schedule_cfg (id) VALUES (1);

        CREATE TABLE IF NOT EXISTS watcher_cfg (
            id          INTEGER PRIMARY KEY,
            enabled     INTEGER DEFAULT 0,
            watch_dirs  TEXT    DEFAULT '[]'
        );
        INSERT OR IGNORE INTO watcher_cfg (id) VALUES (1);

        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        -- Cross-scan file memory (Bug fix: files that already passed a
        -- scan clean were being re-flagged and re-verified from scratch
        -- on every subsequent scan). Keyed by path+mtime+size rather than
        -- content hash so the pre-check is a cheap os.stat() with no file
        -- I/O — a real content change always moves size and/or mtime, so
        -- this is a fast, reliable "has this file changed" signal.
        CREATE TABLE IF NOT EXISTS cleared_files (
            file_path   TEXT PRIMARY KEY,
            mtime       REAL    NOT NULL,
            size        INTEGER NOT NULL,
            verdict     TEXT    NOT NULL,
            cleared_at  TEXT    NOT NULL
        );
    """)
    conn.commit()

    # Safe migration: add VT columns for DBs created before this version.
    # ALTER TABLE ADD COLUMN fails harmlessly if the column already exists.
    for col, coltype in (
        ("vt_checked", "INTEGER DEFAULT 0"),
        ("vt_verdict", "TEXT"),
        ("vt_source",  "TEXT"),
        ("vt_cleared", "INTEGER DEFAULT 0"),
    ):
        try:
            conn.execute(f"ALTER TABLE threats ADD COLUMN {col} {coltype}")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists — fine

    conn.close()


# ── Scans ─────────────────────────────────────────────────────────────────────

def save_scan(
    scan_type: str,
    files_scanned: int,
    threats_found: int,
    shield_score: int,
    duration_sec: float,
    path_scanned: str = "",
    threat_list: Optional[List[Dict]] = None,
) -> int:
    conn = get_db()
    ts = datetime.now().isoformat()
    cur = conn.execute(
        """INSERT INTO scans
           (scan_type, path_scanned, files_scanned, threats_found, shield_score, duration_sec, timestamp)
           VALUES (?,?,?,?,?,?,?)""",
        (scan_type, path_scanned, files_scanned, threats_found, shield_score, duration_sec, ts),
    )
    scan_id = cur.lastrowid

    if threat_list:
        for t in threat_list:
            conn.execute(
                """INSERT INTO threats
                   (scan_id, file_path, risk_score, details, mitre_id, mitre_name,
                    vt_checked, vt_verdict, vt_source, vt_cleared, timestamp)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id,
                    t.get("file", ""),
                    t.get("risk_score", 0),
                    json.dumps(t.get("details", [])),
                    t.get("mitre_id", ""),
                    t.get("mitre_name", ""),
                    int(bool(t.get("vt_checked", False))),
                    t.get("vt_verdict") or "",
                    t.get("vt_source") or "",
                    int(bool(t.get("vt_cleared", False))),
                    ts,
                ),
            )
    conn.commit()
    conn.close()
    return scan_id


def get_scan_history(limit: int = 50) -> List[Dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_threats_for_scan(scan_id: int) -> List[Dict]:
    """
    Returns threats for a scan with a `file` key aliasing the database's
    `file_path` column, matching the shape of a fresh in-memory scan result.
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM threats WHERE scan_id = ? ORDER BY risk_score DESC", (scan_id,)
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d["details"])
        except Exception:
            d["details"] = []
        d["file"] = d.get("file_path", "")
        d["vt_checked"] = bool(d.get("vt_checked", 0))
        d["vt_cleared"] = bool(d.get("vt_cleared", 0))
        result.append(d)
    return result


def get_latest_scan() -> Optional[Dict]:
    conn = get_db()
    row = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if row:
        s = dict(row)
        s["threats"] = get_threats_for_scan(s["id"])
        return s
    return None


# ── VirusTotal cache ──────────────────────────────────────────────────────────

VT_TTL_HOURS = 24


def vt_get_cache(file_hash: str) -> Optional[Dict]:
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT result_json, created_at FROM vt_cache WHERE file_hash = ?",
            (file_hash,),
        ).fetchone()
        conn.close()
        if row:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(
                row["created_at"]
            ).replace(tzinfo=timezone.utc)
            if age < timedelta(hours=VT_TTL_HOURS):
                return json.loads(row["result_json"])
    except Exception:
        pass
    return None


def vt_set_cache(file_hash: str, result: Dict) -> None:
    try:
        conn = get_db()
        conn.execute(
            "INSERT OR REPLACE INTO vt_cache (file_hash, result_json, created_at) VALUES (?,?,?)",
            (file_hash, json.dumps(result), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_vt_cache_count() -> int:
    """
    Total VirusTotal results currently cached (any age). This is a
    completely separate system from the YARA rules Update Intel
    downloads — a person can reasonably confuse the two, since both are
    "threat intelligence" in a loose sense. Exposed via /api/engine/vt-status
    so Settings can show it without conflating it with Update Intel.
    """
    try:
        conn = get_db()
        row = conn.execute("SELECT COUNT(*) as c FROM vt_cache").fetchone()
        conn.close()
        return row["c"] if row else 0
    except Exception:
        return 0


# ── Multi-source threat-intel cache ──────────────────────────────────────────
# Reuses the vt_cache table (same TTL, same shape) under provider-prefixed
# keys (e.g. "multi:<sha256>") so every hash/IP-based provider shares one
# cache without a schema migration. The table name is a legacy holdover
# from when it only cached VirusTotal — it now caches any provider's result.

def intel_get_cache(cache_key: str) -> Optional[Dict]:
    return vt_get_cache(cache_key)


def intel_set_cache(cache_key: str, result: Dict) -> None:
    vt_set_cache(cache_key, result)


# ── Cross-scan file memory ("cleared once, skip until changed") ─────────────

def get_cleared_file(file_path: str, mtime: float, size: int) -> Optional[Dict]:
    """
    Returns the cached clean verdict for this exact file if one exists and
    the file hasn't changed since (path+size exact match, mtime within a
    1-second tolerance to absorb filesystem timestamp rounding). Returns
    None if the file is new, has never been cleared, or has changed.
    """
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM cleared_files WHERE file_path = ?", (file_path,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        if row["size"] != size or abs(row["mtime"] - mtime) > 1.0:
            return None  # file has changed since it was cleared
        return dict(row)
    except Exception:
        return None


def mark_file_cleared(file_path: str, mtime: float, size: int, verdict: str = "clean") -> None:
    try:
        conn = get_db()
        conn.execute(
            """INSERT OR REPLACE INTO cleared_files (file_path, mtime, size, verdict, cleared_at)
               VALUES (?,?,?,?,?)""",
            (file_path, mtime, size, verdict, datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def clear_all_file_verdicts() -> int:
    """
    Invalidate the entire cleared-files cache. Called after a successful
    YARA rules update — new rules might catch something on a file that
    passed cleanly before, so everything needs a fresh look at least once
    after intel changes. Returns the number of entries removed.
    """
    try:
        conn = get_db()
        cur = conn.execute("DELETE FROM cleared_files")
        count = cur.rowcount
        conn.commit()
        conn.close()
        return count
    except Exception:
        return 0


def get_cleared_files_count() -> int:
    try:
        conn = get_db()
        row = conn.execute("SELECT COUNT(*) as c FROM cleared_files").fetchone()
        conn.close()
        return row["c"] if row else 0
    except Exception:
        return 0


# ── Schedule config ───────────────────────────────────────────────────────────

def get_schedule_cfg() -> Dict:
    conn = get_db()
    row = conn.execute("SELECT * FROM schedule_cfg WHERE id=1").fetchone()
    conn.close()
    return dict(row) if row else {}


def save_schedule_cfg(enabled: bool, scan_type: str, frequency: str, hour: int, minute: int) -> None:
    conn = get_db()
    conn.execute(
        """UPDATE schedule_cfg SET enabled=?,scan_type=?,frequency=?,hour=?,minute=?
           WHERE id=1""",
        (int(enabled), scan_type, frequency, hour, minute),
    )
    conn.commit()
    conn.close()


# ── Watcher config ────────────────────────────────────────────────────────────

def get_watcher_cfg() -> Dict:
    conn = get_db()
    row = conn.execute("SELECT * FROM watcher_cfg WHERE id=1").fetchone()
    conn.close()
    if row:
        d = dict(row)
        try:
            d["watch_dirs"] = json.loads(d["watch_dirs"])
        except Exception:
            d["watch_dirs"] = []
        return d
    return {"enabled": 0, "watch_dirs": []}


def save_watcher_cfg(enabled: bool, watch_dirs: List[str]) -> None:
    conn = get_db()
    conn.execute(
        "UPDATE watcher_cfg SET enabled=?,watch_dirs=? WHERE id=1",
        (int(enabled), json.dumps(watch_dirs)),
    )
    conn.commit()
    conn.close()


# ── Generic app settings (VT/OTX/AbuseIPDB persisted API keys, etc.) ────────

def get_setting(key: str, default: str = "") -> str:
    try:
        conn = get_db()
        row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
        conn.close()
        return row["value"] if row and row["value"] is not None else default
    except Exception:
        return default


def set_setting(key: str, value: str) -> None:
    try:
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?,?)", (key, value))
        conn.commit()
        conn.close()
    except Exception:
        pass
