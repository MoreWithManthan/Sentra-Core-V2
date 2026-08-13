# Changelog

## v2.3.0 (this delivery) — Priority-based file selection; scan cap raised

Custom/Deep scans on large systems were silently truncating at `MAX_SCAN_FILES = 10,000` — confirmed by an earlier real scan report showing exactly "Files Scanned: 10000". Since `os.walk()` traverses in a consistent order, this meant the same subset of files got scanned (and the same remainder never did) on every single run, with no indication this had happened.

Fixed:
- **`MAX_SCAN_FILES` raised from 10,000 to 25,000.**
- **New: priority-based selection.** When a scan target has more matching files than the cap, every candidate is now scored (`_priority_score()`) by extension risk tier (direct-execution/scripts > macro-enabled Office > archives > plain Office docs > `.dll` — weighted this way because `.dll` files are both the most numerous on a typical system and, per this project's own scan history, the single biggest source of false-positive noise), common drop-location (`temp`/`downloads`/`desktop`/etc.), and recency (files modified in the last 7/30/180 days score progressively higher). Only the highest-priority files up to the cap are kept, instead of whichever the walk happened to reach first.
- **New: `WALK_CEILING = 150,000`** — a safety backstop on the raw candidate-collection walk (set well above the analysis cap, so there's real material to prioritize among), preventing a pathological target (e.g. a huge network mount) from collecting indefinitely.
- **New: truncation is now visible.** When a target has more candidates than the cap, an `info` WebSocket message reports the total found, how many are being scanned, and how many lower-priority files were left out this run.
- Applied uniformly to **both** Quick Scan and Deep/Custom Scan via one shared `_collect_prioritized_files()` function, replacing two separate ad-hoc walk loops (Quick Scan also picked up the `_is_excluded()` directory-exclusion check it was previously missing, as a side effect of unifying the two code paths).

Verified with real temporary directory structures, not just compiled: confirmed high-priority files (recent `.exe` in a "temp" dir) all survive a cap that low-priority files (400-day-old `.dll` elsewhere) get cut from, confirmed the under-cap case returns everything unmodified, and confirmed excluded directories are still correctly skipped.

---

## v2.3.0 (Phase 1 follow-up, latest) — Install-blocking bugs: marker actually applied, watcher.py crash fixed

### My mistake, now corrected
In the previous dependency-audit pass, I verified your `; python_version < "3.14"` marker fix was syntactically correct — but never actually applied it to the `requirements.txt`/`pyproject.toml` I shipped. You hit the exact same yara-python build failure again as a direct result. Both files now genuinely carry the marker (re-verified with `packaging.requirements.Requirement(...).marker.evaluate(...)`, confirmed False on 3.14 / True on 3.12–3.13, and confirmed `pyproject.toml` still parses as valid TOML).

### Real bug found and fixed — `watcher.py` crashed on import without `watchdog`
`class _Handler(FileSystemEventHandler):` sat unconditionally at module scope, inheriting directly from a name that only exists if `import watchdog` succeeded. Python evaluates base classes immediately when the `class` statement runs — so the surrounding `try/except ImportError` (clearly intended to degrade gracefully) never actually protected against this; the module crashed with `NameError: name 'FileSystemEventHandler' is not defined` the moment it was imported without watchdog installed. This is a pre-existing bug in the original codebase, not something introduced in Phase 1 — it just hadn't been exercised until watchdog was genuinely missing.

Fixed by guarding the class definition itself behind `if _WATCHDOG:`. Verified both paths directly: imported `watcher.py` in a real environment with watchdog *not* installed (`_Handler` becomes `None`, `start()` returns early, no crash) and with it installed (`_Handler` is a real, instantiable class) — not just a compile check.

Ran a systematic AST-based audit across the entire backend for this exact bug class (a name imported inside `try/except ImportError`, used unconditionally at module scope afterward, outside a function or ternary) — `watcher.py` was the only offender; `scheduler.py`, `yara_scanner.py`, and `report_generator.py` all already guard correctly.

### Explained: why unrelated packages (psutil, fastapi) went missing too
When yara-python's wheel build fails, `pip install -r requirements.txt` aborts as a unit — none of the other packages in the file get installed either, even though their wheels resolved and downloaded first. This is now documented directly in `requirements.txt` so it's not surprising next time a single line fails.

### Flagged: `dotenv` vs `python-dotenv` package collision
Manually running `pip install dotenv` to patch a missing import installs a *different, unrelated* legacy package that happens to share the same top-level module name as `python-dotenv` — both write to a module literally called `dotenv`, and one can silently overwrite the other's files. Documented directly in `requirements.txt` with the correct recovery command (`pip uninstall dotenv -y` then reinstall `python-dotenv`).

---

## v2.3.0 (Phase 1 follow-up) — Attribution, observability, signature fallback, scan memory

### Issue A — Reports/UI hardcoded "VirusTotal" regardless of actual source
`report_generator.py` was never updated when the multi-source waterfall was introduced — every cleared file's PDF note said "confirmed clean by VirusTotal" even when MalwareBazaar, OTX, or a digital signature actually cleared it. Fixed: every label now reads the real `vt_source` field. The "VT" column in the Detected Threats table was renamed "Verdict" since the check behind it is no longer VirusTotal-only.

### Issue B — Couldn't verify OTX/AbuseIPDB were actually being used
Two causes, both addressed:
- **Structural:** AbuseIPDB and URLhaus only fire on network/IP checks (Quick Scan's network findings, or a manual "Check Reputation" click in Network tab) — they were never going to show activity from a Deep or Custom scan. Settings now has an explicit note explaining this scope split.
- **Observability:** added session-scoped request counters to all four providers (`malwarebazaar.py`, `otx.py`, `abuseipdb.py`, `urlhaus.py`), mirroring the existing VirusTotal counter pattern, surfaced in Settings so usage is verifiable from inside the app instead of cross-checking each provider's own external dashboard.
- Also fixed: `otx.py` was labeling "zero pulses found" as verdict `"clean"` — OTX has no detection engine of its own, so absence of pulses is "no evidence," not a positive safety confirmation. Now correctly reported as `"not_found"`.

### Issue C — VirusTotal `not_found` had no fallback
Real-world evidence (a Deep Scan report) showed dozens of legitimate Microsoft/vendor resource DLLs flagged purely on heuristics (entropy), with every hash-based source correctly saying "not found" — a genuine database-coverage gap, not something any of the four services could resolve by being queried harder.

Added: **`engine/signature_check.py`** — Windows Authenticode signature verification via the same PowerShell-subprocess pattern already used in `defender.py`. Wired into `threat_intel.py` as the final waterfall tier: if MalwareBazaar, OTX, and VirusTotal all come back inconclusive, a validly-signed file is now treated as clean. If nothing resolves it — not even a signature — the item's score is reduced (via new `INCONCLUSIVE_SCORE_CAP`) but it stays visible in the active list rather than either disappearing or staying at full severity forever.

### Issue D (new feature) — Cross-scan file memory
Every scan previously re-analyzed every file from zero, with no memory of previous results. Added:
- New `cleared_files` table (`database.py`) keyed by path+mtime+size.
- `_scan_file()` now checks this cache first (cheap `os.stat()`, no file I/O) and skips files that passed clean and haven't changed since.
- Files cleared via the threat-intel waterfall are also persisted, not just files that pass heuristics/YARA outright.
- The cache is fully invalidated after a successful "Update Intel" run, since new YARA rules might catch something on a file that passed before.
- New "Force full re-scan" toggle in `ScanModal` bypasses the cache when you deliberately want a fresh check of everything.
- New Settings section ("Scan Memory") shows how many files are currently remembered as clean.

### Bug fix found during this pass
`StartupItems.jsx` and `NetworkMonitor.jsx` both defaulted any non-malicious/non-suspicious verdict to safe-green, which would have mis-colored the new "unknown" (inconclusive) verdict as confirmed-safe. Fixed to require an explicit "clean" match before using the safe color, matching the pattern `ThreatFeed.jsx` already used correctly.

---

## v2.3.0 (Phase 1) — Multi-provider threat intel + dependency audit

### Bug fixes
1. **Quick Scan finishing too early** — expanded `_get_quick_dirs()` (added
   Desktop, Documents, roaming temp, Windows Update cache), raised the file
   cap from 300 to 2000, and increased walk depth. (`backend/main.py`)
2. **VirusTotal capped at top-10 files** — removed the cap entirely; every
   suspicious finding is now checked, backed by a MalwareBazaar → OTX →
   VirusTotal waterfall so the free/unlimited tiers absorb most of the
   volume. (`backend/main.py`, `backend/engine/threat_intel.py`)
3. **Same-name files inheriting each other's VT verdict** — the frontend
   was matching live results by filename (`endsWith`); replaced with a
   unique `id` assigned per result at scan time. (`backend/main.py`,
   `backend/engine/models.py`, `src/hooks/useWebSocket.js`)
4. **YARA-Forge Extended rule set integrated** — 10,735 curated rules now
   vendored as an offline fallback plus fetched from source with dedup
   safety against the old hand-picked source list. (`backend/engine/updater.py`,
   `backend/engine/rules/yara_forge_extended.yar`, `backend/requirements.txt`
   — yara-python was previously commented out)
5. **Microsoft system DLLs flagged as false positives** — added a known-
   system-file allowlist, and YARA matches are now filtered by rule
   severity metadata (an informational-only rule match no longer scores
   the same as an actual malware-family detection). (`backend/engine/heuristics.py`,
   `backend/engine/yara_scanner.py`)
6. **Settings panel had no working scrollbar** — the tab wrapper wasn't a
   flex container, so the panel's own `overflow-y-auto` never had a
   bounded height to actually scroll within. (`src/App.jsx`,
   `src/components/SettingsPanel.jsx`)
7. **Hardcoded API key** — none found in any file reviewed; `.env.example`,
   `.gitignore`, and `k8s/backend/secret.yaml` all use placeholders only.
   Recommend checking your actual `.env` and git history directly.

### New: multi-source threat intelligence
Added MalwareBazaar (unlimited, no key), AlienVault OTX (free key,
uncapped), AbuseIPDB (free key, 1k/day), and URLhaus (unlimited, no key)
alongside VirusTotal, orchestrated by a new `threat_intel.py` aggregator.
Settings panel gained a section to manage the new provider keys.

### Dependency audit (this pass)
- **Removed unused Python packages:** `aiofiles`, `pydantic-settings` —
  confirmed via an AST-based scan of every import in `backend/`, neither
  is referenced anywhere.
- **Verified clean install** in a fresh Python 3.12 venv: `pip install -r
  requirements.txt` + `pip check` + `import main` all succeed.
- **Documented compatibility constraint:** yara-python has no Python 3.14
  wheel yet (wheels exist for 3.9–3.13) — a Python-version issue, not a
  package-version one. See `requirements.txt` header and
  `DEPENDENCY_NOTES.md`.
- **Found and fixed a broken production build:** `vite.config.js` set
  `minify: 'terser'` without `terser` ever being a listed dependency —
  `npm run build` failed outright. Switched to Vite's built-in `esbuild`
  minifier (zero extra dependency, verified working).
- **Added the missing `package-lock.json`** — `Dockerfile.frontend` runs
  `npm ci`, which requires a lockfile that didn't exist anywhere in the
  project. Generated and verified against the finalized `package.json`.
- **Bumped major versions where verified safe, documented where not:**
  `vite` -> 5.4.x (patches a real Vite-authored CVE; a separate esbuild
  advisory is a documented non-issue for Vite consumers), `recharts` -> v3
  (v2 is maintainer-declared EOL; verified the exact exports this codebase
  uses still exist), `framer-motion` -> v12, `react-circular-progressbar`
  -> v2.2. Deliberately **kept React on v18** rather than jumping to v19 in
  the same pass as three other major bumps — see `DEPENDENCY_NOTES.md` for
  full reasoning on every pin.
- **Full end-to-end verification:** ran the actual production build
  (`npm ci` + `npm run build`) against the real application source, not
  just individual package installs — 1042 modules transformed, valid
  CSS/JS bundle produced. This is also how the previously-missing
  `CleanupModal.jsx` file was caught during this reconstruction.

See `DEPENDENCY_NOTES.md` for the full reasoning behind every version
choice, and `backend/requirements.txt` / `package.json` for the final pins.

---
Baseline reference: `SENTRA_CORE_CODEBASE.md` (v2.5.0) describes the
pre-Phase-1 architecture and is otherwise still accurate — component
structure, API routes, WebSocket protocol, and DB schema are unchanged
except where noted above.
