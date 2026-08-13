# SENTRA CORE — Complete Codebase Reference
> Version: **2.3.0** | Stack: **FastAPI + React 18 + SQLite** | Optional: **Tauri desktop wrapper**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Tech Stack & Dependencies](#2-tech-stack--dependencies)
3. [Repository Structure](#3-repository-structure)
4. [Architecture & Data Flow](#4-architecture--data-flow)
5. [Backend — Deep Dive](#5-backend--deep-dive)
   - 5.1 [main.py — FastAPI Application Core](#51-mainpy--fastapi-application-core)
   - 5.2 [database.py — SQLite Persistence Layer](#52-databasepy--sqlite-persistence-layer)
   - 5.3 [scheduler.py — Automatic Scan Scheduling](#53-schedulerpy--automatic-scan-scheduling)
   - 5.4 [watcher.py — Filesystem Auto-Scanner](#54-watcherpy--filesystem-auto-scanner)
   - 5.5 [engine/models.py — Pydantic Data Models](#55-enginemodelspy--pydantic-data-models)
   - 5.6 [engine/heuristics.py — File Analysis Engine](#56-engineheuristicspy--file-analysis-engine)
   - 5.7 [engine/virustotal.py — VirusTotal API v3 Client](#57-enginevirustotalpy--virustotal-api-v3-client)
   - 5.8 [engine/yara_scanner.py — YARA Rule Scanner](#58-engineyara_scannerpy--yara-rule-scanner)
   - 5.9 [engine/mitre_mapper.py — MITRE ATT&CK Mapper](#59-enginemitre_mapperpy--mitre-attck-mapper)
   - 5.10 [engine/network_monitor.py — Network Connection Monitor](#510-enginenetwork_monitorpy--network-connection-monitor)
   - 5.11 [engine/startup_scanner.py — Startup Items Detector](#511-enginestartup_scannerpy--startup-items-detector)
   - 5.12 [engine/defender.py — Windows Defender Integration](#512-enginedefenderpy--windows-defender-integration)
   - 5.13 [engine/parallel_scanner.py — Concurrent File Scanner](#513-engineparallel_scannerpy--concurrent-file-scanner)
   - 5.14 [engine/system_optimize.py — System Maintenance](#514-enginesystem_optimizepy--system-maintenance)
   - 5.15 [engine/updater.py — YARA Intelligence Updater](#515-engineupdaterpy--yara-intelligence-updater)
   - 5.16 [engine/report_generator.py — PDF Report Generator](#516-enginereport_generatorpy--pdf-report-generator)
   - 5.17 [engine/malwarebazaar.py — MalwareBazaar Client](#517-enginemalwarebazaarpy--malwarebazaar-client)
   - 5.18 [engine/otx.py — AlienVault OTX Client](#518-engineotxpy--alienvault-otx-client)
   - 5.19 [engine/abuseipdb.py — AbuseIPDB Client](#519-engineabuseipdbpy--abuseipdb-client)
   - 5.20 [engine/urlhaus.py — URLhaus Client](#520-engineurlhauspy--urlhaus-client)
   - 5.21 [engine/signature_check.py — Digital Signature Verification](#521-enginesignature_checkpy--digital-signature-verification)
   - 5.22 [engine/threat_intel.py — Multi-Source Aggregator](#522-enginethreat_intelpy--multi-source-aggregator)
6. [Frontend — Deep Dive](#6-frontend--deep-dive)
   - 6.1 [src/App.jsx — Root Application Component](#61-srcappjsx--root-application-component)
   - 6.2 [src/services/api.js — REST API Client](#62-srcservicesapijs--rest-api-client)
   - 6.3 [src/hooks/useWebSocket.js — WebSocket Hooks](#63-srchooksusewebsocketjs--websocket-hooks)
   - 6.4 [Components Reference](#64-components-reference)
7. [Tauri Desktop Wrapper](#7-tauri-desktop-wrapper)
8. [API Reference — All Endpoints](#8-api-reference--all-endpoints)
9. [WebSocket Protocol](#9-websocket-protocol)
10. [Database Schema](#10-database-schema)
11. [Configuration & Environment Variables](#11-configuration--environment-variables)
12. [Scan Pipeline — End-to-End Flow](#12-scan-pipeline--end-to-end-flow)
13. [Scoring System](#13-scoring-system)
14. [Infrastructure — Docker & Kubernetes](#14-infrastructure--docker--kubernetes)
15. [Key Constants & Limits](#15-key-constants--limits)
16. [Dependency Management](#16-dependency-management)
17. [Known-Issue History](#17-known-issue-history)
18. [Glossary of Internal Terms](#18-glossary-of-internal-terms)

---

## 1. Project Overview

SENTRA CORE is a **cross-platform cybersecurity dashboard and system optimizer**. It combines real-time system telemetry, multi-strategy malware detection backed by five independent threat-intelligence sources, and automated remediation into a single application.

**Core capabilities:**
- Real-time CPU/memory telemetry streamed over WebSocket every 1 second
- Multi-layered file threat scanning: heuristics → YARA rules (10,700+ curated rules via YARA-Forge Extended, severity-filtered) → multi-source reputation verification → digital-signature fallback
- **Multi-source threat intelligence**: every suspicious finding is checked against MalwareBazaar and AlienVault OTX (both free/unlimited) before falling through to VirusTotal's rate-limited free tier, and — if none of the three have ever seen the exact file — a Windows Authenticode signature check. No top-N cutoff: every flagged item gets checked.
- **Per-provider usage tracking**: session request counters for all five sources, visible in Settings, so it's verifiable from inside the app whether a provider actually fired.
- **Cross-scan file memory**: a file that already passed a scan clean is skipped on future scans (by path/size/mtime) until it actually changes, rather than being re-analyzed from zero every time. Invalidated automatically after a YARA rules update.
- Live network connection monitoring, cross-checked against AbuseIPDB, URLhaus, and VirusTotal simultaneously
- Windows startup item inspection with registry scanning
- Scheduled automatic scans (daily / weekly / monthly via cron)
- Filesystem watchdog — auto-scans newly created executable files in watched folders
- System optimization: temp file cleanup, DNS flush, platform-specific deep clean
- Windows Defender integration for exclusion management and SFC/DISM system repair
- PDF report generation from any historical scan, with dynamic per-row provider attribution
- MITRE ATT&CK framework attribution on every detected threat

**Deployment modes:**
- **Dev mode**: Vite dev server (port 5173) + Python backend (port 8000) running side-by-side
- **Docker Compose**: containerized backend + Nginx-served frontend behind a reverse proxy
- **Kubernetes**: full K8s manifests with HPA, Ingress, PVCs, Secrets
- **Tauri desktop app**: wraps React UI in a native window, spawns the Python backend as a sidecar process

---

## 2. Tech Stack & Dependencies

> Every version below was verified together in a clean install (Python 3.12 venv; Node 22/npm 10). Full reasoning for every pinned floor — including which are hard compatibility constraints versus routine bumps — lives in `DEPENDENCY_NOTES.md`. This section reflects the *result* of that audit.

### Backend (Python 3.10+)

| Package | Purpose |
|---|---|
| `fastapi >= 0.115` | REST API + WebSocket server |
| `uvicorn[standard] >= 0.30` | ASGI server |
| `websockets >= 13.0` | WebSocket protocol support |
| `python-dotenv >= 1.0.1` | `.env` file loading |
| `psutil >= 6.0` | CPU, memory, process, disk, network stats |
| `requests >= 2.32` | HTTP client — used directly and by every threat-intel provider client |
| `pydantic >= 2.9` | Data validation and serialization |
| `reportlab >= 4.2` | PDF report generation |
| `apscheduler >= 3.10.4` | Cron-based scheduled scans |
| `watchdog >= 4.0` | Filesystem change monitoring |
| `yara-python >= 4.5; python_version < "3.14"` | YARA rule matching |

**Removed as unused** (confirmed via an AST-based scan of every import statement in every `.py` file, not a text grep): `aiofiles`, `pydantic-settings`.

**Hard compatibility constraint — yara-python and Python 3.14:** yara-python publishes prebuilt wheels for CPython 3.9–3.13 only; there is no Python 3.14 wheel as of this release. The environment marker above tells pip to skip the line entirely on 3.14 rather than attempting — and failing — a source build that needs a C++ toolchain. **Important:** a single package failing to build aborts the *entire* `pip install -r requirements.txt` command, not just that package — if you ever see unrelated `ModuleNotFoundError`s right after a build failure, re-run the full install rather than patching packages in by hand. See `requirements.txt`'s header comments for the full explanation, including a warning about the `dotenv`/`python-dotenv` package-name collision (they are two different, unrelated packages that both install a module literally called `dotenv`).

### Frontend (Node 20+)

| Package | Purpose |
|---|---|
| `react ^18.3.1` | UI framework (deliberately not bumped to 19 — see DEPENDENCY_NOTES.md) |
| `react-dom ^18.3.1` | DOM rendering |
| `framer-motion ^12.0.0` | Animations |
| `recharts ^3.0.0` | CPU/memory time-series charts (v2 branch is maintainer-declared EOL) |
| `react-circular-progressbar ^2.2.0` | Shield score gauge |
| `vite ^5.4.12` | Build tool and dev server — this floor patches a real Vite-authored CVE |
| `@vitejs/plugin-react ^4.3.4` | Vite React plugin |
| `tailwindcss ^3.4.17` | Utility-first CSS — deliberately not upgraded to v4 (breaking rewrite) |
| `autoprefixer ^10.4.20` | CSS vendor prefix automation |
| `postcss ^8.4.47` | CSS transform pipeline |

**Fixed during dependency verification — the production build was silently broken:** `vite.config.js` previously set `build.minify: 'terser'` without `terser` ever being listed as a dependency (optional since Vite 3). `npm run build` — the exact command `Dockerfile.frontend` runs — failed outright. Fixed by switching to Vite's built-in `esbuild` minifier. A `package-lock.json` was also missing entirely despite `Dockerfile.frontend` running `npm ci` (which requires one); one has been generated and verified against the final `package.json`.

### Desktop (Rust — optional)
| Crate | Purpose |
|---|---|
| `tauri` | Native window framework |
| `tauri-plugin-shell` | Spawn the Python backend sidecar |
| `tauri-plugin-notification` | System notifications |

---

## 3. Repository Structure

```
sentra-core/
├── backend/
│   ├── main.py                    # FastAPI app — all REST endpoints + WebSocket handlers
│   ├── database.py                # SQLite layer — scans, threats, intel cache, cleared-files memory, settings
│   ├── scheduler.py                # APScheduler wrapper for automatic scans
│   ├── watcher.py                  # Watchdog filesystem monitor
│   ├── requirements.txt            # Python dependency list (verified, documented, marker-gated yara-python)
│   ├── pyproject.toml              # Project metadata (kept in sync with requirements.txt)
│   └── engine/
│       ├── __init__.py
│       ├── models.py                # All Pydantic request/response models
│       ├── heuristics.py            # File analysis engine (entropy, signatures, location, MS-system allowlist)
│       ├── virustotal.py            # VirusTotal API v3 client — one tier in the threat-intel waterfall
│       ├── yara_scanner.py          # YARA rule compilation + severity-aware match filtering
│       ├── mitre_mapper.py          # MITRE ATT&CK keyword → technique mapping
│       ├── network_monitor.py       # psutil network connections + suspicious port detection
│       ├── startup_scanner.py       # Windows registry Run keys + startup folder scanner
│       ├── defender.py              # Windows Defender exclusion management (PowerShell)
│       ├── parallel_scanner.py      # ThreadPoolExecutor-backed async file scanner
│       ├── system_optimize.py       # Temp cleanup, DNS flush, DISM/purge/apt deep clean
│       ├── updater.py               # Downloads YARA-Forge Extended + supplementary rules, with dedup safety
│       ├── report_generator.py      # ReportLab PDF report generator — dynamic per-row provider attribution
│       ├── malwarebazaar.py         # MalwareBazaar hash-lookup client (no key, unlimited) + usage stats
│       ├── otx.py                   # AlienVault OTX hash/IoC client (free key, uncapped) + usage stats
│       ├── abuseipdb.py             # AbuseIPDB IP-reputation client (free key, 1k/day) + usage stats
│       ├── urlhaus.py               # URLhaus domain/host reputation client (no key, unlimited) + usage stats
│       ├── signature_check.py       # Windows Authenticode signature verification (VT-not-found fallback)
│       ├── threat_intel.py          # Waterfall/merge aggregator across all five sources + signature check
│       └── rules/
│           ├── .gitkeep
│           ├── yara_forge_extended.yar  # Vendored offline fallback, 10,735 rules
│           └── active_threats.yar   # Generated at runtime via "Update Intel" (git-ignored)
│
├── src/
│   ├── main.jsx                    # React entry point
│   ├── App.jsx                     # Root component — state, routing, modal logic
│   ├── index.css                   # Global styles + CSS custom properties (theme vars)
│   ├── hooks/
│   │   ├── useWebSocket.js          # useTelemetry + useScanWS hooks — id-based result matching
│   │   └── useApi.js                # Generic API hook (unused in current version)
│   ├── services/
│   │   └── api.js                   # All REST API calls, incl. intel-status/intel-key/cleared-files-count
│   └── components/
│       ├── TopNav.jsx                # Navigation bar with tabs, theme switcher, action buttons
│       ├── StatusCards.jsx           # CPU / memory / threats summary cards
│       ├── ShieldGauge.jsx           # Circular progress bar for shield score
│       ├── SystemGraph.jsx           # Recharts time-series for CPU + memory
│       ├── ProcessMonitor.jsx        # Top processes by CPU usage
│       ├── ThreatFeed.jsx            # Live threat list — shows which provider verified each item
│       ├── NetworkMonitor.jsx        # Active connections table with merged threat-intel check
│       ├── StartupItems.jsx          # Startup entries with risk badges + reputation check
│       ├── ScanHistory.jsx           # Past scan list with expandable threat details
│       ├── SettingsPanel.jsx         # VT/OTX/AbuseIPDB keys, usage counters, scan memory, schedule, watcher, defender, theme
│       ├── ScanModal.jsx             # Scan type selector — verification toggle + "Force full re-scan"
│       ├── CleanupModal.jsx          # Cleanup + deep clean + system repair options
│       ├── VTKeyModal.jsx            # First-run VirusTotal API key prompt
│       ├── IntelModal.jsx            # Post-update result display
│       ├── ScheduleModal.jsx         # Schedule config (frequency, time)
│       ├── Toast.jsx                 # Toast notification system (context + hook)
│       ├── Modal.jsx                 # Base modal component with ModalBtn
│       └── ErrorBoundary.jsx         # React error boundary with reset
│
├── src-tauri/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs                  # Tauri entry — system tray, backend sidecar spawn
│
├── k8s/
│   ├── namespace.yaml
│   ├── hpa.yaml                     # HorizontalPodAutoscaler
│   ├── ingress.yaml                 # Nginx Ingress with /api routing
│   ├── backend/
│   │   ├── deployment.yaml          # 2-replica deployment + PVC for YARA rules + 3 provider secret keys
│   │   ├── service.yaml
│   │   ├── configmap.yaml
│   │   └── secret.yaml              # VT_API_KEY, OTX_API_KEY, ABUSEIPDB_API_KEY placeholders
│   └── frontend/
│       ├── deployment.yaml
│       └── service.yaml
│
├── docker/
│   └── nginx.conf                   # Nginx config — /api proxy + SPA fallback
│
├── public/
│   └── favicon.svg
│
├── Dockerfile.backend               # Multi-stage: builder + slim runtime (non-root), Python 3.11 (has yara wheels)
├── Dockerfile.frontend              # Multi-stage: node build + nginx serve
├── docker-compose.yml               # Backend + frontend services + 3 provider env vars + yara_rules volume
├── vite.config.js                   # Vite config — dev proxy for /api and /ws; esbuild minifier
├── tailwind.config.js               # Tailwind theme extensions
├── package.json                     # name: sentra-core, version: 2.3.0
├── package-lock.json                # Required by `npm ci` in Dockerfile.frontend
├── index.html                       # HTML entry point
├── postcss.config.js
├── .env.example                     # Documents all env vars incl. OTX_API_KEY / ABUSEIPDB_API_KEY
├── .gitignore                       # Ensures .env, generated rules, and DB files are never committed
├── DEPENDENCY_NOTES.md              # Full reasoning behind every pinned dependency version
└── CHANGELOG.md                     # Full history of fixes across every delivery of this project
```

---

## 4. Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                          BROWSER / TAURI WINDOW                     │
│                                                                     │
│  ┌────────────────────┐   ┌───────────────────────────────────────┐ │
│  │  React App (SPA)   │   │       useWebSocket hooks               │ │
│  │  App.jsx           │   │  useTelemetry → /ws/telemetry (1s)    │ │
│  │  ├─ TopNav         │   │  useScanWS   → /ws/scan (streaming,   │ │
│  │  ├─ Dashboard      │   │                id-matched results)    │ │
│  │  │  ├─ StatusCards │   └───────────────────────────────────────┘ │
│  │  │  ├─ ShieldGauge │                    │ WS frames               │
│  │  │  ├─ SystemGraph │                    ▼                        │
│  │  │  ├─ ProcessMon  │   ┌───────────────────────────────────────┐ │
│  │  │  └─ ThreatFeed  │   │       api.js (REST)                   │ │
│  │  ├─ NetworkMonitor │   │  fetch() with AbortController timeout │ │
│  │  ├─ StartupItems   │   └───────────────────────────────────────┘ │
│  │  ├─ ScanHistory    │                    │ HTTP                    │
│  │  └─ SettingsPanel  │                    │                        │
│  └────────────────────┘                    │                        │
└───────────────────────────────────────────────────────────────────┘
                                             │
                              ┌──────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FastAPI BACKEND (port 8000)                       │
│                                                                     │
│  main.py                                                            │
│  ├─ /api/health                           GET                       │
│  ├─ /ws/telemetry                         WebSocket (1s loop)       │
│  ├─ /ws/scan                              WebSocket (streaming,     │
│  │                                        force_rescan-aware)       │
│  ├─ /api/system/*                         GET system data           │
│  ├─ /api/actions/*                        POST cleanup/repair       │
│  ├─ /api/engine/*                         POST scan/VT/update/      │
│  │                                        intel-status/intel-key/   │
│  │                                        cleared-files-count       │
│  ├─ /api/history/*                        GET scan history          │
│  ├─ /api/reports/generate                 POST → PDF bytes          │
│  ├─ /api/schedule                         GET/POST cron config      │
│  └─ /api/watcher                          GET/POST watchdog config  │
│                                                                     │
│  _scan_file(fp, skip_cleared=True)                                   │
│       │                                                              │
│       ├─► cleared_files cache hit? ──► skip entirely (cheap stat())  │
│       │                                                              │
│       ▼                                                              │
│  heuristics → yara_scanner (severity-filtered) → mitre_mapper        │
│                     │                                                │
│                     ▼ (only for already-flagged results)             │
│         ┌───────────────────────────────────────┐                   │
│         │   threat_intel.py (aggregator)        │                   │
│         │                                        │                   │
│         │  Hash waterfall (files):               │                   │
│         │   MalwareBazaar → OTX → VirusTotal     │                   │
│         │   → signature_check (Windows, final)   │                   │
│         │                                        │                   │
│         │  IP merge (network):                   │                   │
│         │   AbuseIPDB + URLhaus + VirusTotal      │                   │
│         │                                        │                   │
│         │  clean result ──► db.mark_file_cleared()│                  │
│         └───────────────────────────────────────┘                   │
│  network_monitor → startup_scanner → parallel_scanner               │
│  system_optimize → report_generator → updater → defender            │
│                                                                     │
│  SQLite (sentra.db)                                                 │
│  ├─ scans           (scan history)                                   │
│  ├─ threats         (per-scan threat records, incl. vt_source)      │
│  ├─ vt_cache        (24h cache — shared by every intel provider,    │
│  │                   keyed by provider-prefixed cache keys)         │
│  ├─ cleared_files   (cross-scan memory — path+mtime+size → verdict) │
│  ├─ schedule_cfg    (singleton row)                                  │
│  ├─ watcher_cfg     (singleton row)                                  │
│  └─ app_settings    (key-value, stores VT/OTX/AbuseIPDB API keys)   │
└─────────────────────────────────────────────────────────────────────┘
```

**Key communication patterns:**

1. **Telemetry WebSocket** (`/ws/telemetry`): Backend sends CPU, memory, process list, network connections, and scan history every 1 second. Non-telemetry events (intel update complete, repair done, deep optimize done, scheduled scan done) are multiplexed on the same connection and routed by `msg.type` in the frontend's `handleWsEvent` callback.

2. **Scan WebSocket** (`/ws/scan`): Client opens connection, sends config JSON (`type`, `path`, `verify_vt`, `force_rescan`), then receives a stream of typed messages (`started`, `progress`, `info`, `threat`, `vt_start`, `vt_result`, `complete`, `error`). The backend does not wait for the full scan to finish before sending results — each threat is pushed as soon as it's found. Every threat carries a unique `id`, and `vt_result` messages reference results by that `id` rather than by filename.

3. **Cross-scan file memory**: before any real analysis, `_scan_file()` checks whether the exact file (path+mtime+size) already passed a previous scan clean. If so, it's skipped entirely — no heuristics, no YARA, no I/O beyond a single `os.stat()` call. A file that passes clean (either outright, or after being cleared by the threat-intel waterfall) is recorded so future scans skip it too, until it changes. The cache is invalidated wholesale after a successful "Update Intel" run.

4. **Threat-intel waterfall/merge** (`threat_intel.py`): File-hash lookups try MalwareBazaar first (instant, unlimited, no key), then AlienVault OTX if configured (instant, uncapped), then VirusTotal (rate-limited to ~4 req/min on the free tier). If none of the three have ever seen the exact hash, a Windows Authenticode signature check is tried as a final tier — a validly-signed file is treated as clean even with zero hash-database hits. If nothing resolves it at all, the finding's score is reduced but stays visible for a human look rather than disappearing or staying at full severity. IP/network lookups instead *merge* AbuseIPDB, URLhaus, and VirusTotal simultaneously and take the worst verdict.

5. **REST API**: All other operations use standard `fetch()` calls with `AbortController` timeouts. The `APIError` class captures HTTP status, message, and body for error display.

6. **WSManager** (`main.py`): Maintains a list of all active WebSocket connections and broadcasts structured JSON to all of them. Background tasks (scheduled scans, deep optimize, repair) use this to push completion events to the UI.

---

## 5. Backend — Deep Dive

### 5.1 `main.py` — FastAPI Application Core

**Module-level constants:**
```python
MIN_THREAT_SCORE      = 25     # Minimum combined score to report a threat
MAX_SCAN_FILES         = 10000  # Hard cap on files per deep/custom scan
QUICK_CAP              = 2000   # Quick Scan file cap (raised from an original 300)
VT_CLEARED_SCORE_CAP   = 5      # Score assigned to genuinely-clean items
INCONCLUSIVE_SCORE_CAP = 15     # Score assigned when NOTHING resolves a finding —
                                 # weaker evidence than a real "clean", so the item
                                 # is demoted but stays visible, not hidden
```

**Excluded directories** (never walked during any scan):
```
venv, .venv, node_modules, __pycache__, site-packages, .git,
dist, build, .next, .idea, .vscode, Scripts, Include, Lib, bin, lib
```

---

**Key private functions:**

`_is_excluded(path)` / `_is_critical(path)` — path-based filters (excluded dirs; Windows critical-path detection for admin warnings).

`_get_quick_dirs()` → `List[str]`
Quick Scan directories — expanded beyond the original short list: `%USERPROFILE%\AppData\Local\Temp`, `Downloads`, `Desktop`, `Documents`, `AppData\Roaming\Temp`, the Windows INetCache folder, `%TEMP%`, `%TMP%`, `C:\Windows\Temp`, `C:\Windows\Prefetch`, `C:\$Recycle.Bin` (Windows); `/tmp`, `/var/tmp`, `~/Downloads`, `~/Desktop`, `~/Documents`, `~/.cache` (Linux/macOS).

`_normalize_scan_path(path)` / `_extract_executable_path(raw)` — path normalization helpers (bare drive letters, quoted registry Run values).

`_walk_with_diagnostics(root, max_depth, stats)` → generator of file paths
Recursive walk shared by every scan type. Counts permission errors, folders visited, files examined so a low-result scan can be explained (`_diagnose_low_results`) instead of looking identical to "nothing here."

`_scan_file(fp, skip_cleared=True)` → `Optional[Dict]`
**Core single-file scan pipeline, now with cross-scan memory:**
1. If `skip_cleared` (default True): `os.stat()` the file and check `db.get_cleared_file(fp, mtime, size)`. If it matches a prior clean verdict, **return None immediately** — no heuristics, no YARA, no I/O beyond the stat call.
2. Otherwise: `analyze_file(fp)` for heuristic score + findings, `scan_with_yara(fp)` for matches, filtered to only `actionable` matches (informational/low-severity rule hits are excluded from scoring).
3. `score = min(heuristic_score + yara_score, 100)`, where `yara_score = min(actionable_match_count * 30, 60)`.
4. If `score >= MIN_THREAT_SCORE` or any actionable match: build a result dict with a fresh `id = uuid.uuid4().hex`, `enrich_result()` it with MITRE attribution, and return it.
5. **Otherwise (passed cleanly):** record it via `db.mark_file_cleared(fp, mtime, size)` so future scans skip it entirely.

The `skip_cleared=False` path is reached via a `functools.partial(_scan_file, skip_cleared=not force_rescan)` built in `ws_scan()` from the client's `force_rescan` flag — this lets a single scan bypass the cache without changing the function's default behavior for the scheduled/REST scan paths, which always use the cache.

`_network_findings()` / `_startup_findings()` → `List[Dict]`
Suspicious network connections / startup entries, each formatted as a threat dict with a fresh `id`, `type` (`"network"`/`"startup"`), and MITRE attribution. **Only ever added during a Quick Scan** — this is the reason AbuseIPDB/URLhaus never fire on a Deep or Custom scan (see §5.22 and the Settings panel's scope note).

`_run_blocking(fn, *args)` → coroutine
Wraps a synchronous function in `loop.run_in_executor(None, fn, *args)`.

`_verify_with_threat_intel(results, ws)` → coroutine
Checks **every** result in `results` against the multi-source waterfall/merge (no top-N cutoff — this only became tractable once MalwareBazaar/OTX absorbed most of the volume ahead of VirusTotal's rate limit). For each result:
- `type == "network"` → `threat_intel.check_ip_reputation_multi(target)`, source recorded as `"multi-source"`.
- otherwise → `threat_intel.check_file_reputation(target)`, source read from the result's own `source` field (`malwarebazaar`/`otx`/`virustotal`/`signature`/`none`).
- `verdict == "clean"` → `vt_cleared = True`, score capped at `VT_CLEARED_SCORE_CAP`, and — for file-type results — persisted via `db.mark_file_cleared()` so it's skipped on the next scan too.
- `verdict == "unknown"` (checked everywhere, including a signature check, nothing conclusive) → score capped at `INCONCLUSIVE_SCORE_CAP`, but **not** marked cleared — stays visible for a human look.
- Every step sends a `vt_result` WebSocket message keyed by the result's `id` (not filename — see §Known-Issue-History).

---

**`WSManager` class:** unchanged — maintains all active WebSocket connections, provides `broadcast()`.

**`_scheduled_scan()`** (async): Quick Scan over `_get_quick_dirs()`, saves to DB, broadcasts `scheduled_scan_complete`. Uses `_scan_file(fp)` with default `skip_cleared=True`.

**Lifespan context manager** (startup/shutdown):
1. `db.init_db()` — creates/migrates tables, including `cleared_files`
2. `load_persisted_key()` (VirusTotal) + `threat_intel.load_all_persisted_keys()` (OTX, AbuseIPDB)
3. Scheduler + watcher startup (unchanged)
4. `setup_sentra_exclusions()` (Windows Defender)

**`/ws/scan` handler additions:**
- Reads `force_rescan` from the client config; builds `scan_fn = functools.partial(_scan_file, skip_cleared=not force_rescan)` and passes that (not the bare `_scan_file`) into `scan_files_streaming()`.
- `verify_vt` no longer requires a VirusTotal key — MalwareBazaar/URLhaus need none, so "verify everything" is meaningful even with zero keys configured.

**New endpoints:**
- `GET /api/engine/intel-status` — returns `ThreatIntelStatus`: configured booleans for OTX/AbuseIPDB/VirusTotal, plus a `ProviderUsage` block (request count, last result, last request time) for all four non-VT providers.
- `POST /api/engine/intel-key` — generic key setter for `{"provider": "otx"|"abuseipdb", "api_key": "..."}`.
- `GET /api/engine/cleared-files-count` — `{"count": N}`, how many files are currently remembered as clean.

**`network_vt_check` / `startup_vt_check`:** now call `threat_intel.check_ip_reputation_multi` / `threat_intel.check_file_reputation` respectively, instead of calling VirusTotal directly.

**`_do_update()`:** after a successful rules update, also calls `db.clear_all_file_verdicts()` — new YARA rules might catch something on a file that passed clean before, so the cross-scan cache is wiped wholesale and every file gets one fresh look under the new rules. The invalidated-entry count is appended to the update result's message.

### 5.2 `database.py` — SQLite Persistence Layer

Every function opens a fresh connection, executes its query, and closes it. WAL journal mode and foreign keys enabled on every connection.

**`init_db()`** creates all tables idempotently, plus safe `ALTER TABLE` migrations for `threats.vt_source` (added alongside `vt_checked`/`vt_verdict`/`vt_cleared`).

**Scan / VT-cache functions:** unchanged from earlier versions — `save_scan`, `get_scan_history`, `get_threats_for_scan`, `get_latest_scan`, `vt_get_cache`/`vt_set_cache` (24h TTL), `get_vt_cache_count`.

**Multi-source intel cache:** `intel_get_cache(cache_key)` / `intel_set_cache(cache_key, result)` are thin wrappers around `vt_get_cache`/`vt_set_cache`, letting every provider share one cache table under provider-prefixed keys (e.g. `"multi:<sha256>"`) without a schema migration.

**Cross-scan file memory (new table):**
```sql
CREATE TABLE cleared_files (
    file_path   TEXT PRIMARY KEY,
    mtime       REAL    NOT NULL,
    size        INTEGER NOT NULL,
    verdict     TEXT    NOT NULL,
    cleared_at  TEXT    NOT NULL
);
```
- `get_cleared_file(file_path, mtime, size)` → matching row or `None`. Exact match on `size`; `mtime` compared with a 1-second tolerance to absorb filesystem timestamp rounding. Any mismatch (or no row) returns `None`, meaning "scan this fresh."
- `mark_file_cleared(file_path, mtime, size, verdict="clean")` — `INSERT OR REPLACE`.
- `clear_all_file_verdicts()` → count of rows deleted. Called after a successful rules update.
- `get_cleared_files_count()` → total rows, surfaced in Settings.

**Settings functions:** `get_setting`/`set_setting` — generic key-value store, used to persist VT/OTX/AbuseIPDB API keys across restarts.

---

### 5.3 `scheduler.py` — Automatic Scan Scheduling
Unchanged. Wraps APScheduler's `AsyncIOScheduler`; gracefully degrades if `apscheduler` isn't installed (guarded correctly — see §17).

---

### 5.4 `watcher.py` — Filesystem Auto-Scanner

Uses `watchdog`'s `Observer`/`FileSystemEventHandler`; gracefully degrades if `watchdog` isn't installed.

**Fixed bug (see §17):** the `_Handler` class definition — which inherits from `FileSystemEventHandler` — used to sit unconditionally at module scope. Python evaluates a class's base classes the instant the `class` statement executes, so importing this module without `watchdog` installed crashed with `NameError: name 'FileSystemEventHandler' is not defined`, defeating the surrounding `try/except ImportError`'s clear intent to degrade gracefully. Now the entire class definition is wrapped in `if _WATCHDOG:`, with `_Handler = None` in the `else` branch. Every call site (`start()`) already returned early when `_WATCHDOG` is False, so nothing else needed to change. Verified directly (not just compiled) in both states: watchdog present (real class, instantiates) and absent (`_Handler is None`, `start()` returns cleanly, no crash).

`default_watch_dirs()` — Windows: `~/Downloads`, `~/Desktop`, `%TEMP%`. Linux/macOS: `~/Downloads`, `/tmp`.

---

### 5.5 `engine/models.py` — Pydantic Data Models

Key models (additions marked **NEW**):

| Model | Purpose |
|---|---|
| `ProcessInfo`, `StatsEntry` | Telemetry shapes |
| `ScanResult` | Full threat record — **NEW:** `id` (unique per-result identifier), `vt_source` (which provider produced the verdict) |
| `CleanupRequest`/`CleanupResult`, `IntelligenceUpdate`, `IntelMetadata` | Unchanged |
| `CustomScanRequest`/`CustomScanResponse` | Unchanged |
| `VTScanRequest`/`VTScanResult`/`VTBatchRequest`, `IPReputationRequest`, `StartupVTCheckRequest`, `VTUsageStatus`, `VTKeyRequest` | Unchanged (still used by the VT-specific admin endpoints) |
| **NEW** `ProviderKeyRequest` | Generic `{provider, api_key}` setter for OTX/AbuseIPDB |
| **NEW** `ProviderUsage` | Session-scoped `{requests_made, last_request_at, last_result}` for one provider |
| **NEW** `ThreatIntelStatus` | Configured booleans + a `ProviderUsage` block for each of MalwareBazaar/OTX/AbuseIPDB/URLhaus |
| **NEW** `IPReputationResult` | `{status, ip, verdict, sources, checked_sources}` — the merged network-check shape |
| `DriveInfo`/`DrivesResponse`, `DefenderExclusionRequest`/`Response`, `ScheduleConfig`, `WatcherConfig`, `ReportRequest`, `RepairStatus` | Unchanged |

---

### 5.6 `engine/heuristics.py` — File Analysis Engine

Extension categories, entropy analysis, and category-specific scoring (`_analyze_executable`/`_analyze_archive`/`_analyze_document`/`_analyze_unknown`) are unchanged from the original design — see §13 for the full scoring table.

**Added — known-Microsoft-system-file allowlist:**
```python
_MS_SYSTEM_DIR_MARKERS = ("system32", "syswow64", "winsxs")
_MS_KNOWN_SAFE_NAMES = {"ntdll.dll", "kernel32.dll", ..., "ntoskrnl.exe"}  # ~19 core DLLs

def _is_known_microsoft_system_file(file_path: str) -> bool:
    # True only if the file's NAME is a known core DLL AND it's actually
    # sitting in a genuine system directory — an identically-named file
    # dropped elsewhere is still analyzed normally.
```
`analyze_file()` checks this first and returns `{"findings": [...], "score": 0}` immediately if matched — before entropy/temp-dir scoring ever runs. This is a name+location allowlist, not a full Authenticode check (that's `signature_check.py`, applied later in the pipeline to a much wider set of files, not just core OS DLLs — see §5.21).

---

### 5.7 `engine/virustotal.py` — VirusTotal API v3 Client

Unchanged in its own logic (rate limiting at `_MIN_INTERVAL = 15.1s`, session stats, hash caching, IP reputation, `test_connection()` via the EICAR hash). What changed is *how it's called*: `main.py` no longer calls `scan_file`/`check_ip_reputation` directly for scan verification — those now go through `threat_intel.py`, which treats VirusTotal as one waterfall tier rather than the only check. The `/api/engine/vt-scan`, `/api/engine/vt-batch`, `/api/engine/vt-key`, `/api/engine/vt-test`, `/api/engine/vt-status` endpoints still call this module directly for the manual/admin VT-specific flows.

---

### 5.8 `engine/yara_scanner.py` — YARA Rule Scanner

`RULES_PATH` defaults to `backend/engine/rules/active_threats.yar`. `_compiled_rules` cached after first load; `invalidate_cache()` resets it after an "Update Intel" run.

**Added — severity-aware match filtering:**
```python
_LOW_SIGNAL_CATEGORIES = {"info"}
_MIN_ACTIONABLE_SCORE = 40

def _is_actionable(match_meta: Dict) -> bool:
    # False for matches whose rule metadata marks them "info" category,
    # or whose meta.score is below the threshold — YARA-Forge tags every
    # rule with category/score/importance, and a purely informational
    # rule (e.g. a certificate-blocklist entry) matching a benign file
    # shouldn't score the same as an actual malware-family detection.
```
`scan_with_yara()` now returns each match with an `"actionable": bool` flag alongside `rule`/`tags`/`meta`. Callers (`_scan_file` in `main.py`) only count actionable matches toward score/reporting, while all matches are still available for context.

---

### 5.9 `engine/mitre_mapper.py` — MITRE ATT&CK Mapper
Unchanged. 20 techniques, keyword-based mapping, `enrich_result()` no-ops if `mitre_id` already set.

---

### 5.10 `engine/network_monitor.py` — Network Connection Monitor
Unchanged. Suspicious-port set, `psutil.net_connections()`-based, sorted suspicious-first.

---

### 5.11 `engine/startup_scanner.py` — Startup Items Detector
Unchanged. Windows-only; registry Run/RunOnce keys + Startup folder.

---

### 5.12 `engine/defender.py` — Windows Defender Integration
Unchanged. PowerShell-subprocess pattern (`_is_admin`, `add_exclusion`, `get_exclusions`, `setup_sentra_exclusions`) — this is the pattern `signature_check.py` (§5.21) follows for its own PowerShell call.

---

### 5.13 `engine/parallel_scanner.py` — Concurrent File Scanner
Unchanged. `ThreadPoolExecutor(max_workers=6)`, `scan_files_streaming()` accepts any `scan_fn: Callable[[str], Optional[Dict]]` — this is what lets `main.py` pass a `functools.partial(_scan_file, skip_cleared=...)` in without any change to this module.

---

### 5.14 `engine/system_optimize.py` — System Maintenance
Unchanged. `quick_optimize()` (temp cleanup + DNS flush), `deep_optimize()` (platform-specific: DISM ResetBase / macOS purge+cache clear / Linux package-cache clean + journal vacuum).

---

### 5.15 `engine/updater.py` — YARA Intelligence Updater

Primary source is now the **YARA-Forge Extended package** (10,000+ curated, quality-filtered rules aggregated upstream from ReversingLabs, Neo23x0, and others), fetched as a zip and extracted in-memory. A small supplementary source list (`YARA-Rules/MALW_Eicar`, `MALW_Ransomware_Ryuk`, `MALW_Ransomware_WannaCry`) is layered on top, with **rule-name deduplication** — any supplementary file whose rule identifiers fully collide with what's already loaded is skipped, since `yara.compile()` fails outright on duplicate identifiers and YARA-Forge already re-packages most community rule sets.

`_fetch_yara_forge()` falls back to a **vendored offline copy** (`rules/yara_forge_extended.yar`, 10,735 rules) if the network is unreachable, so scanning still works offline.

`update_threat_database()` returns the same result shape as before (`status`, `message`, `rules_updated`, `sources_ok`, `sources_failed`, `timestamp`, `path`) — `main.py`'s `_do_update()` appends a note about invalidated cross-scan cache entries to `message` after a successful run.

---

### 5.16 `engine/report_generator.py` — PDF Report Generator

**Fixed bug (see §17):** every label used to hardcode "VirusTotal" regardless of which provider actually produced a verdict — a leftover from before the multi-source waterfall existed. Now:
```python
_SOURCE_LABELS = {
    "malwarebazaar": "MalwareBazaar", "otx": "AlienVault OTX",
    "virustotal": "VirusTotal", "signature": "Digital Signature",
    "multi-source": "Threat Intelligence",
}
def _source_label(r: Dict) -> str:
    return _SOURCE_LABELS.get(r.get("vt_source"), "Threat Intelligence")
```
- "Verified Safe by VirusTotal" → **"Verified Safe (Multi-Source Threat Intelligence)"**; each row's note now reads `f"Flagged locally, confirmed clean by {_source_label(r)}"`.
- The Detected Threats table's "VT" column is renamed **"Verdict"** (the check behind it isn't VT-only anymore); the specific provider name is shown in the Verified Safe section below where there's room.
- Generic recommendation text softened from "Use the VirusTotal check..." to "Use the built-in reputation check..." since there are now multiple sources.
- Footer version string corrected to match the rest of the app (`v2.3.0`).

Everything else — A4 layout, color palette, summary table, `MAX_PDF_ROWS = 150`, dynamic recommendations based on shield score — is unchanged.

### 5.17 `engine/malwarebazaar.py` — MalwareBazaar Client

No API key required, unlimited free tier. First tier in the file-hash waterfall.

`lookup_hash(sha256)` → `POST https://mb-api.abuse.ch/api/v1/` with `{query: "get_info", hash: sha256}`.
- `query_status == "hash_not_found"` → `{"status": "not_found"}`
- `query_status == "ok"` → `{"status": "success", "source": "malwarebazaar", "verdict": "malicious", signature, file_type, first_seen, tags, permalink}` — everything present in MalwareBazaar is a confirmed submitted malware sample; there's no "suspicious" tier for this source.

**Usage tracking:** module-level `_stats = {requests_made, last_request_at, last_result}`, incremented via `_record_request()` on every call (including errors/timeouts, which record a descriptive summary). `get_stats()` returns a copy. Surfaced via `/api/engine/intel-status` → Settings.

---

### 5.18 `engine/otx.py` — AlienVault OTX Client

Free API key, high/effectively-uncapped quota. Second tier in the file-hash waterfall — only checked if `has_api_key()`.

`lookup_hash(sha256)` → `GET /api/v1/indicators/file/{sha256}/general` with `X-OTX-API-KEY` header.
- `pulse_count > 0` → `{"status": "success", "source": "otx", "verdict": "malicious", pulse_count, permalink}`
- `pulse_count == 0` (or 404) → **`{"status": "not_found", ...}`**

**Fixed bug:** this used to report zero pulses as verdict `"clean"`. OTX has no detection engine of its own — a pulse count of zero means "no evidence either way," not a positive safety confirmation, so only VirusTotal (which aggregates real AV engine scans) or a valid digital signature can produce a genuinely definitive "clean." `check_file_reputation()` in `threat_intel.py` only short-circuits on OTX when `verdict == "malicious"`; anything else falls through to VirusTotal.

Key persistence pattern is identical to `virustotal.py`: `has_api_key()`, `set_api_key()` (updates the module global + persists via `database.set_setting`), `load_persisted_key()` (restores from DB at startup if `.env` didn't provide one).

**Usage tracking:** same `_stats`/`get_stats()` pattern as MalwareBazaar.

---

### 5.19 `engine/abuseipdb.py` — AbuseIPDB Client

Free API key, 1,000 requests/day. **Only used for network/IP checks** — never during a file scan.

`check_ip(ip)` → `GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90` with `Key` header.
- `abuseConfidenceScore >= 75` → `"malicious"`; `>= 25` → `"suspicious"`; else `"clean"`.
- Returns `{status, source: "abuseipdb", ip, verdict, abuse_confidence_score, total_reports, country, isp, permalink}`.

Same key-persistence pattern (`has_api_key`/`set_api_key`/`load_persisted_key`) and usage-tracking pattern as OTX.

**Scope note** (also surfaced directly in Settings): this only fires during Quick Scan's network findings, or a manual "Check Reputation" click in the Network tab. A Deep or Custom scan will never show activity here — that's expected, not a bug.

---

### 5.20 `engine/urlhaus.py` — URLhaus Client

No API key required, unlimited free tier. Same scope restriction as AbuseIPDB (network/IP checks only).

`check_host(host)` → `POST https://urlhaus-api.abuse.ch/v1/host/` with `{host}`.
- `query_status == "no_results"` → `{"status": "not_found"}`
- `query_status == "ok"` → verdict is `"malicious"` if any returned URL has `url_status == "online"`, `"suspicious"` if there are URLs but none currently online, else `"clean"`.

Usage tracking identical to the other three.

---

### 5.21 `engine/signature_check.py` — Digital Signature Verification

**New module.** Windows Authenticode verification via the same PowerShell-subprocess pattern already established in `defender.py`. This is the actual fix for a real-world failure mode: a Deep Scan report showed dozens of legitimate Microsoft/vendor resource DLLs flagged purely on heuristics (entropy), with MalwareBazaar, OTX, *and* VirusTotal all correctly saying "not found" — a genuine hash-database coverage gap that no amount of re-querying the same three sources can close.

`check_signature(file_path)` runs:
```powershell
$s = Get-AuthenticodeSignature -LiteralPath $env:SENTRA_SIG_CHECK_PATH
if ($s.SignerCertificate) { $subj = $s.SignerCertificate.Subject } else { $subj = '' }
Write-Output "$($s.Status)|$subj"
```
The file path is passed via an **environment variable**, not interpolated into the script string — this means a path containing quotes or other special characters can never break out of the intended command (no injection surface).

Returns:
- `{"status": "valid", "signer": "..."}` — `Get-AuthenticodeSignature` reported `Valid`; signer is the certificate's CN extracted from the subject string.
- `{"status": "not_signed"}` — no signature present at all.
- `{"status": "invalid", "signer": "...", "detail": "..."}` — signed but `HashMismatch`/`NotTrusted`/`Expired`/etc.
- `{"status": "unavailable", "message": "..."}` — non-Windows, PowerShell error, or timeout (15s).

Windows-only; every other platform gets `"unavailable"` immediately with no subprocess call.

---

### 5.22 `engine/threat_intel.py` — Multi-Source Aggregator

The central orchestrator. Two entry points:

**`check_file_reputation(file_path)`** — the hash waterfall:
1. Hash the file (SHA-256); check the shared `"multi:<hash>"` cache first.
2. **MalwareBazaar** — if it confirms malicious, return immediately (cached).
3. **OTX** (if configured) — if it confirms malicious, return immediately (cached).
4. **VirusTotal** — the only one of the three capable of a genuinely definitive `"clean"` (it aggregates ~70 real AV engine scans; the other two are detection databases, not scanners).
5. If VT's own status is `not_found`/`error`/`no_key` (i.e., the hash-based waterfall found nothing conclusive either way): try **`signature_check.check_signature()`**.
   - Valid signature → `{"status": "success", "source": "signature", "verdict": "clean", "signer": ...}`.
   - Otherwise → the result's `status` is overwritten to `"inconclusive"`, `verdict` to `"unknown"`, and **`source` to `"none"`** (not left as `"virustotal"` — leaving it would misleadingly imply VT specifically confirmed something, when in fact nothing did).

**`check_ip_reputation_multi(ip)`** — the network merge: calls AbuseIPDB (if configured), URLhaus, and VirusTotal's IP endpoint, then takes the worst verdict across whichever returned successfully (`malicious` > `suspicious` > `clean`/`not_found`). Returns `{status, ip, verdict, sources: {...per-provider raw results...}, checked_sources: [...]}` so the UI can show exactly which providers actually answered.

**`get_all_provider_stats()`** — returns `{malwarebazaar, otx, abuseipdb, urlhaus}`, each a `get_stats()` dict from that provider's own module. This is what powers the Settings panel's per-provider usage counters.

**`load_all_persisted_keys()`** — called once at backend startup (`main.py`'s lifespan), restores OTX/AbuseIPDB keys from the database alongside VirusTotal's own restore.

---

## 6. Frontend — Deep Dive

### 6.1 `src/App.jsx` — Root Application Component

Theme system, state management (`tab`, `modal`, `vtKey`/`vtConfigured` self-heal effect, telemetry/scan hooks) are unchanged from earlier versions.

**Fixed bug:** the Settings tab's wrapper (`<div className="flex-1 min-h-0 h-full overflow-hidden">`) wasn't a flex container, so `SettingsPanel`'s own `overflow-y-auto` grid never had a bounded height to actually scroll *within* — it just grew, and the wrapper silently clipped the excess. Now `flex flex-col` is added to the wrapper, giving the panel real height to size against.

**`handleScanStart`** now destructures and forwards `force_rescan` alongside `type`/`path`/`verify_vt` into `startScan()`.

**`Panel`** component (reusable flex container with title/badge/action slot) is unchanged.

---

### 6.2 `src/services/api.js` — REST API Client

Core `req()` wrapper (AbortController timeout, `APIError` class) unchanged. New exports:
```javascript
getIntelStatus()              GET  /api/engine/intel-status
setIntelKey(provider, key)    POST /api/engine/intel-key
getClearedFilesCount()        GET  /api/engine/cleared-files-count
```
`checkIpReputation`/`checkStartupItemVt` still point at the same endpoints — only the backend logic behind them changed (now multi-source instead of VT-only).

---

### 6.3 `src/hooks/useWebSocket.js` — WebSocket Hooks

`useTelemetry` unchanged.

**Fixed bug in `useScanWS`:** the `vt_result` handler used to match live results back to threat rows by filename (`(t.file || '').endsWith(msg.file)`). Two different files sharing a basename (different folders, different hashes) would incorrectly inherit each other's verdict — checking one bled its result onto the other in the UI. Now matches strictly on each result's unique `id`:
```javascript
setThreats(prev => prev.map(t =>
  (msg.id && t.id === msg.id)
    ? { ...t, vt_checked: true, vt_verdict: msg.verdict, vt_source: msg.source }
    : t
));
```

---

### 6.4 Components Reference

**`TopNav.jsx`** — navigation bar. **Incidental fix found during reconstruction:** the active-tab indicator had two duplicate JSX `style` props on the same element (`style={{background, border}} style={{zIndex: -1}}`) — the second silently overwrote the first, dropping the indicator's background/border entirely. Merged into one style object.

**`SettingsPanel.jsx`** — significantly expanded:
- *VirusTotal Integration* / *VirusTotal Usage* — unchanged.
- **New: "Additional Threat Intelligence"** section — `AlwaysActiveBadge` (MalwareBazaar/URLhaus) and `ProviderKeyRow` (OTX/AbuseIPDB) both now display a live request count (`usage.requests_made`) alongside configured/active status, polled every 10s via `getIntelStatus()`. Includes an explicit scope-clarification note: *MalwareBazaar/OTX/VirusTotal check files (any scan type); AbuseIPDB/URLhaus check network connections only (Quick Scan or manual Network-tab checks) — Deep/Custom scans will never show activity for those two.*
- **New: "Scan Memory"** section — shows the live `cleared-files-count`, with a one-line explanation of the skip-if-unchanged behavior and a pointer to the "Force full re-scan" toggle.
- *Scheduled Scans*, *Auto-Scan Watchdog*, *Windows Defender*, *Accent Theme* — unchanged.
- *About* — version/description text updated to reflect the current feature set.

**`ScanModal.jsx`** — the verification toggle is no longer VT-gated (copy changed from "top 10 highest-risk files" to "Checks all suspicious findings... no cutoff"), and the `vtConfigured` prop is no longer read (MalwareBazaar/URLhaus work with zero keys, so there's nothing to gate on). **New: "Force full re-scan" toggle**, wired into `onStart({..., force_rescan})`.

**`ThreatFeed.jsx`** — `SOURCE_LABELS` extended with `signature: 'Signed'` and `none: 'Unreviewed'`; the active-item badge now reads `{sourceLabel}: {verdict}` instead of a hardcoded `VT:` prefix. Color logic already correctly required an explicit `'clean'` match before using safe-green (no bug here).

**`NetworkMonitor.jsx`** / **`StartupItems.jsx`** — **fixed bug:** both previously defaulted *any* verdict that wasn't `'malicious'`/`'suspicious'` to safe-green, which would have mis-colored the new `'unknown'` (inconclusive) verdict as confirmed-safe. Both now require an explicit `verdict === 'clean'` match before using the safe color, falling back to neutral gray otherwise — matching the pattern `ThreatFeed.jsx` already used correctly. `NetworkMonitor`'s table header renamed "VirusTotal" → "Threat Intel"; `StartupItems`' `SOURCE_LABELS` gained `signature`/`none` entries; both "Check VT" buttons renamed "Check Reputation".

**`CleanupModal.jsx`, `VTKeyModal.jsx`, `IntelModal.jsx`, `ScheduleModal.jsx`, `Toast.jsx`, `Modal.jsx`, `ErrorBoundary.jsx`, `StatusCards.jsx`, `ShieldGauge.jsx`, `SystemGraph.jsx`, `ProcessMonitor.jsx`, `ScanHistory.jsx`** — unchanged.

---

## 7. Tauri Desktop Wrapper

Unchanged. `src-tauri/src/main.rs` — system tray (Open/Quit menu, left-click focuses window), close-to-tray behavior, backend sidecar spawn in release builds (`app.shell().sidecar("sentra-backend").spawn()`, requires the Python backend compiled as an `externalBin` in `tauri.conf.json`; run separately in dev). Plugins: `tauri-plugin-shell`, `tauri-plugin-notification`.

---

## 8. API Reference — All Endpoints

### System Endpoints
| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Backend health check — `{status, version: "2.3.0", timestamp, os}` |
| GET | `/api/system/stats-history` | CPU + memory history |
| GET | `/api/system/processes` | Top 12 processes by CPU |
| GET | `/api/system/drives` | Disk partitions + usage |
| GET | `/api/system/network` | Active connections |
| GET | `/api/system/startup-items` | Startup registry entries |
| POST | `/api/system/network/vt-check` | **Now multi-source** — merges AbuseIPDB + URLhaus + VirusTotal |
| POST | `/api/system/startup/vt-check` | **Now multi-source** — waterfalls MalwareBazaar → OTX → VirusTotal → signature |
| GET | `/api/system/defender/status` | Defender admin + exclusions |
| POST | `/api/system/defender/exclude` | Add Defender exclusion |

### Engine Endpoints
| Method | Path | Description |
|---|---|---|
| GET | `/api/engine/scan` | Quick scan (REST, no streaming) |
| POST | `/api/engine/custom-scan` | Custom path scan |
| POST | `/api/engine/vt-scan` / `/vt-batch` | Manual VirusTotal-specific checks (unchanged) |
| GET | `/api/engine/vt-status` | VirusTotal configuration + usage stats (unchanged) |
| POST | `/api/engine/vt-key` / `/vt-test` | VirusTotal key admin (unchanged) |
| **NEW** GET | `/api/engine/intel-status` | Configured booleans + per-provider `ProviderUsage` for MalwareBazaar/OTX/AbuseIPDB/URLhaus |
| **NEW** POST | `/api/engine/intel-key` | `{provider: "otx"\|"abuseipdb", api_key}` |
| **NEW** GET | `/api/engine/cleared-files-count` | `{"count": N}` — cross-scan memory size |
| POST | `/api/engine/update` | Trigger YARA-Forge + supplementary rules update; also invalidates cross-scan cache on success |
| GET | `/api/engine/intel/metadata` | Local YARA rules info |

### Action / History / Report / Schedule / Watcher Endpoints
Unchanged from earlier versions: `/api/actions/cleanup`, `/api/actions/system-repair`, `/api/actions/repair-status`, `/api/actions/deep-optimize-status`, `/api/history/scans`, `/api/history/scans/{id}/threats`, `/api/history/latest`, `/api/reports/generate`, `/api/schedule` (GET/POST), `/api/watcher` (GET/POST).

### WebSocket Endpoints
| Path | Description |
|---|---|
| `/ws/telemetry` | 1-second telemetry stream + background event channel |
| `/ws/scan` | Bidirectional scan WebSocket — client config now includes `force_rescan` |

---

## 9. WebSocket Protocol

### `/ws/telemetry` — unchanged
Same `telemetry` message shape and background-event multiplexing (`intel_update_complete`, `repair_*`, `deep_optimize_*`, `scheduled_scan_complete`, `auto_threat`) as earlier versions.

### `/ws/scan` — Bidirectional

**Client → Server (initial message):**
```json
{
  "type": "quick" | "deep" | "custom",
  "path": "/some/directory",
  "verify_vt": true,
  "force_rescan": false
}
```
`force_rescan` (new): bypasses the cross-scan cleared-files cache for this scan only.

**Server → Client message types:**

| type | Fields | Notes |
|---|---|---|
| `started` | `scan_type` | |
| `info` | `message` | Admin warning, empty-folder explanation |
| `progress` | `scanned, total, current_file` | `total` counts files matched during the walk, unaffected by cache skips |
| `threat` | `data: {ScanResult fields}` | Now includes `id` and `vt_source` |
| `vt_start` | `count` | Every flagged result — no top-N cutoff |
| `vt_result` | `id, file, verdict, source, cleared, detections, total_engines` | **Keyed by `id`, not filename** — see §17 |
| `complete` | `scan_id, files_scanned, threats_found, shield_score, duration_sec, timestamp` | |
| `error` | `message` | |

---

## 10. Database Schema

```sql
-- Scan records
CREATE TABLE scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type     TEXT NOT NULL,          -- quick | deep | custom | scheduled
    path_scanned  TEXT,
    files_scanned INTEGER DEFAULT 0,
    threats_found INTEGER DEFAULT 0,
    shield_score  INTEGER DEFAULT 100,
    duration_sec  REAL    DEFAULT 0,
    timestamp     TEXT NOT NULL
);

-- Per-scan threats (cascade-deletes with scan)
CREATE TABLE threats (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    risk_score  INTEGER DEFAULT 0,
    details     TEXT,                     -- JSON array of finding strings
    mitre_id    TEXT,
    mitre_name  TEXT,
    vt_checked  INTEGER DEFAULT 0,
    vt_verdict  TEXT,                     -- clean | suspicious | malicious | unknown | null
    vt_source   TEXT,                     -- malwarebazaar | otx | virustotal | signature | none  [NEW]
    vt_cleared  INTEGER DEFAULT 0,
    timestamp   TEXT NOT NULL
);

CREATE INDEX idx_threats_scan ON threats(scan_id);

-- Multi-source threat-intel cache (24h TTL) — table name is a legacy
-- holdover from when it only cached VirusTotal; now shared by every
-- provider under prefixed keys (e.g. "multi:<sha256>")
CREATE TABLE vt_cache (
    file_hash   TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- Cross-scan file memory ("cleared once, skip until changed")  [NEW]
CREATE TABLE cleared_files (
    file_path   TEXT PRIMARY KEY,
    mtime       REAL    NOT NULL,
    size        INTEGER NOT NULL,
    verdict     TEXT    NOT NULL,
    cleared_at  TEXT    NOT NULL
);

-- Schedule config (singleton, id=1)
CREATE TABLE schedule_cfg (
    id        INTEGER PRIMARY KEY,
    enabled   INTEGER DEFAULT 0,
    scan_type TEXT    DEFAULT 'quick',
    frequency TEXT    DEFAULT 'daily',
    hour      INTEGER DEFAULT 2,
    minute    INTEGER DEFAULT 0
);

-- Watcher config (singleton, id=1)
CREATE TABLE watcher_cfg (
    id         INTEGER PRIMARY KEY,
    enabled    INTEGER DEFAULT 0,
    watch_dirs TEXT    DEFAULT '[]'
);

-- Generic settings store
CREATE TABLE app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
-- Keys currently used: vt_api_key, otx_api_key, abuseipdb_api_key
```

---

## 11. Configuration & Environment Variables

| Variable | Default | Description |
|---|---|---|
| `API_HOST` | `127.0.0.1` | Backend bind address |
| `API_PORT` | `8000` | Backend port |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `FRONTEND_URL` | `http://localhost:5173` | CORS allowed origin |
| `RELOAD` | `false` | Uvicorn auto-reload (dev only) |
| `DB_PATH` | `sentra.db` | SQLite database file path |
| `RULES_PATH` | `backend/engine/rules/active_threats.yar` | YARA rules file path |
| `VT_API_KEY` | `` | VirusTotal API key (optional — can also be set via UI) |
| **NEW** `OTX_API_KEY` | `` | AlienVault OTX key (optional — free, high/uncapped quota) |
| **NEW** `ABUSEIPDB_API_KEY` | `` | AbuseIPDB key (optional — free, 1,000/day) |
| `VITE_API_URL` | `` | Frontend API base URL (empty = relative) |
| `VITE_WS_URL` | `ws://localhost:8000` | WebSocket base URL |
| `VITE_API_TIMEOUT` | `30000` | Default API timeout (ms) |

MalwareBazaar and URLhaus need no key at all — always active.

**localStorage keys (frontend):** `sentra-theme`, `sentra_vt_key`, `sentra_vt_asked` — unchanged.

---

## 12. Scan Pipeline — End-to-End Flow

### Quick Scan
1. Frontend opens `/ws/scan` with `{type: "quick", verify_vt, force_rescan}`.
2. Backend sends `started`, warns if non-admin on Windows.
3. `_get_quick_dirs()` returns the expanded directory list (§5.1). Walks each up to depth 4, cap `QUICK_CAP = 2000` files.
4. `scan_files_streaming()` processes files concurrently (6 threads) via `functools.partial(_scan_file, skip_cleared=not force_rescan)`.
5. Each file: cache check (skip if unchanged since last clean) → heuristic + actionable-YARA-only pipeline → threat if score ≥ 25 or actionable match.
6. Adds `_network_findings()` + `_startup_findings()` — **Quick Scan only**.
7. If `verify_vt`: `_verify_with_threat_intel()` checks **every** result (no cutoff) via the waterfall/merge.
8. Shield score calculated, saved to DB, `complete` sent.

### Deep Scan / Custom Scan
Same per-file pipeline, `max_depth=64` (Deep) or user-specified extensions (Custom REST), up to `MAX_SCAN_FILES = 10000`. **No network/startup findings** — this is why AbuseIPDB/URLhaus never show activity here (see §17).

### Scheduled Scan / Auto-Scan (Watcher)
Unchanged — Quick Scan logic via cron (`skip_cleared` defaults True, no force-rescan option exposed there) / single-file heuristic-only scan on new file creation, respectively.

---

## 13. Scoring System

### Per-file threat scoring
| Signal | Score | Applies to |
|---|---|---|
| Entropy > 7.5 / > 7.0 | +35 / +15 | Executables only |
| Located in temp/cache directory | +35 (exec) / +20 (other) | All except known-MS-system files |
| Embedded RAR signature | +15 | Executables |
| Large file / large archive | +5 | Executables / Archives |
| Macro-enabled document | +15 | Documents |
| Each **actionable** YARA rule match | +30 (capped at 60 total) | All — non-actionable (informational/low-score) matches don't count |
| Known Microsoft system file (name+path match) | Score forced to 0 | Executables in System32/SysWOW64/WinSxS |

All scores capped at 100; items below `MIN_THREAT_SCORE = 25` (and with no actionable YARA match) aren't reported at all.

### Post-verification score adjustment
| Waterfall outcome | Effect |
|---|---|
| `verdict == "clean"` (VirusTotal or valid signature) | `vt_cleared = True`, score capped at `VT_CLEARED_SCORE_CAP = 5`, persisted to cross-scan memory |
| `verdict == "unknown"` (nothing conclusive anywhere, including signature check) | score capped at `INCONCLUSIVE_SCORE_CAP = 15`, **not** cleared — stays visible |
| `verdict == "malicious"` (any source) | score/flag unchanged, shown as active threat |

### Shield Score formula (unchanged)
```
combined = (0.7 × max_risk_score) + (0.3 × average_risk_score)
shield   = max(0, 100 − combined)
```

### Verdict resolution order (file hash)
`MalwareBazaar → OTX → VirusTotal → Digital Signature`, stopping at the first definitive answer. See §5.22 for the full waterfall logic.

---

## 14. Infrastructure — Docker & Kubernetes

### Docker Compose
Two services (`backend`, `frontend`) — unchanged structure. Backend now also receives `OTX_API_KEY` and `ABUSEIPDB_API_KEY` env vars (empty-default via `${VAR:-}`). Named volume `sentra_yara_rules` persists YARA rules between restarts.

### Dockerfile.backend
`python:3.11-slim` base — deliberately within yara-python's supported wheel range (3.9–3.13), so the container build never hits the Python 3.14 MSVC issue that affects local Windows dev environments. `gcc`/`libssl-dev`/`libffi-dev` present in the builder stage regardless, as a fallback.

### Dockerfile.frontend
`node:20-alpine`, `npm ci` (now works — a `package-lock.json` exists) → `npm run build` (now works — `vite.config.js` uses the built-in `esbuild` minifier instead of the never-installed `terser`) → served via `nginx:1.25-alpine`.

### Kubernetes
`k8s/backend/secret.yaml` now has three placeholder keys (`VT_API_KEY`, `OTX_API_KEY`, `ABUSEIPDB_API_KEY`); `k8s/backend/deployment.yaml`'s container env wires all three from the secret. `namespace.yaml`, `hpa.yaml`, `ingress.yaml`, `backend/configmap.yaml`/`service.yaml`, `frontend/deployment.yaml`/`service.yaml` are otherwise unchanged.

---

## 15. Key Constants & Limits

| Constant | Value | Location | Purpose |
|---|---|---|---|
| `MIN_THREAT_SCORE` | 25 | main.py | Minimum score to report a threat |
| `MAX_SCAN_FILES` | 10,000 | main.py | Max files per deep/custom scan |
| `QUICK_CAP` | **2,000** (was 300) | main.py | Max files in quick scan |
| `VT_CLEARED_SCORE_CAP` | 5 | main.py | Score assigned to genuinely-clean items |
| **NEW** `INCONCLUSIVE_SCORE_CAP` | 15 | main.py | Score assigned when nothing resolves a finding either way |
| `_MIN_INTERVAL` | 15.1s | virustotal.py | Rate limit between VT requests |
| `VT_TTL_HOURS` | 24 | database.py | Intel cache expiry (shared by all providers) |
| **NEW** cleared-file mtime tolerance | 1.0s | database.py | Absorbs filesystem timestamp rounding in the cross-scan cache check |
| `MAX_PDF_ROWS` | 150 | report_generator.py | Max rows in PDF threat table |
| History buffer | 30 entries | main.py | Rolling telemetry history |
| Scan max_depth | 4 (quick, was 3) / 64 (deep) | main.py | Directory traversal limit |
| Thread pool workers | 6 | parallel_scanner.py | Concurrent scan threads |
| Signature-check timeout | 15s | signature_check.py | Per-file PowerShell subprocess timeout |
| VT batch limit | 50 files | models.py | Max files in batch VT scan |
| Custom scan max | 5,000 files | models.py | Max for REST custom scan |
| Backend check interval | 15s | App.jsx | Health check polling |
| VT/intel status interval | 30s / 10s | App.jsx / SettingsPanel.jsx | Configured-state polling |
| Provider usage counter interval | 5s (VT) / 10s (others) | SettingsPanel.jsx | Live counter polling |
| Cleared-files-count interval | 10s | SettingsPanel.jsx | Scan Memory count polling |

---

## 16. Dependency Management

Full reasoning for every pinned floor lives in `DEPENDENCY_NOTES.md` — this section summarizes the verification methodology.

**Backend:** verified in a clean Python 3.12 virtualenv — `pip install -r requirements.txt` (zero conflicts, `pip check` passes) → `import main` succeeds end-to-end, not just individual package imports. Unused packages (`aiofiles`, `pydantic-settings`) removed via AST-based import scanning of every `.py` file, not a text grep. `yara-python` gated behind a `python_version < "3.14"` environment marker (verified with `packaging.requirements.Requirement(...).marker.evaluate(...)` against 3.12/3.13/3.14), since no prebuilt wheel exists yet for 3.14 and a single failing package aborts the *entire* `pip install` command, not just itself.

**Frontend:** verified with a real `npm ci` + `npm run build` against the actual application source (not a synthetic test) — 1042 modules transformed, valid CSS/JS bundle produced. Major-version bumps (`vite`, `recharts`, `framer-motion`, `react-circular-progressbar`) were each checked individually rather than bumped blindly; React was deliberately kept on v18 to avoid stacking a fourth major-version change in the same pass. A missing `package-lock.json` (required by `Dockerfile.frontend`'s `npm ci`) was generated and verified. A broken `vite.config.js` minifier setting (`'terser'`, never installed) was caught by actually running the build, not just linting — fixed to use Vite's built-in `esbuild`.

**Recurring lesson:** verification means running the actual install/build/import commands end-to-end against the real files being shipped, not just checking syntax or trusting that a previously-verified fix was correctly carried forward into every subsequent delivery — see §17 for a case where it wasn't.

---

## 17. Known-Issue History

A record of real bugs found and fixed across this project's development, kept for context on *why* certain code looks the way it does.

| Issue | Root cause | Fix |
|---|---|---|
| Quick Scan finished too early | Narrow directory list + low file cap (300) | Expanded directory list; `QUICK_CAP` raised to 2,000; walk depth 3→4 |
| VirusTotal capped at top-10 files | Hardcoded `[:VT_MAX_PER_SCAN]` slice | Removed; every flagged result checked via the MalwareBazaar→OTX→VT waterfall |
| Same-name files inherited each other's VT verdict | Frontend matched live results by filename (`endsWith`) | Every result gets a unique `id`; matching is now strict on `id` |
| Microsoft DLLs flagged as suspicious | No allowlist; raw YARA match count scored equally regardless of rule severity | Known-system-file allowlist (heuristics.py) + actionable-only YARA scoring (yara_scanner.py) |
| Settings panel had no working scrollbar | Tab wrapper wasn't a flex container, so the panel's `overflow-y-auto` had no bounded height | Wrapper made `flex flex-col` |
| Reports/UI hardcoded "VirusTotal" regardless of actual source | `report_generator.py` never updated when the multi-source waterfall was introduced | Every label now reads the real `vt_source` field |
| Couldn't verify OTX/AbuseIPDB usage | (a) AbuseIPDB/URLhaus structurally only fire on network checks, never Deep/Custom scans; (b) no in-app usage visibility | (a) documented directly in Settings; (b) per-provider request counters added to all four non-VT providers |
| OTX mislabeled "zero pulses" as `"clean"` | OTX has no detection engine of its own — absence of pulses isn't a positive safety confirmation | Now reported as `"not_found"` |
| VirusTotal `not_found` had no fallback | Real coverage gap — legitimate files no hash database has ever seen | `signature_check.py` added as a final waterfall tier; `INCONCLUSIVE_SCORE_CAP` for genuinely unresolved cases |
| Every scan re-analyzed every file from zero | No persistent memory of prior clean verdicts | `cleared_files` table + `_scan_file`'s `skip_cleared` pre-check; invalidated on rules update; "Force full re-scan" toggle |
| `StartupItems.jsx`/`NetworkMonitor.jsx` mis-colored inconclusive verdicts as safe-green | Both defaulted anything-not-malicious/suspicious to green instead of requiring an explicit `'clean'` match | Explicit `'clean'` check added, matching `ThreatFeed.jsx`'s already-correct pattern |
| `TopNav.jsx` active-tab indicator missing background/border | Duplicate JSX `style` prop on the same element — the second silently overwrote the first | Merged into one style object |
| Production build silently broken | `vite.config.js` set `minify: 'terser'`; `terser` was never a listed dependency (optional since Vite 3) | Switched to Vite's built-in `esbuild` minifier |
| `npm ci` had no lockfile to install from | `package-lock.json` never existed despite `Dockerfile.frontend` requiring one | Generated and verified against the final `package.json` |
| yara-python build failed on Python 3.14 (recurred once) | No prebuilt wheel exists for 3.14; **the environment-marker fix was verified as correct but never actually applied to the shipped file** | Marker genuinely applied this time, re-verified with `packaging`'s own marker evaluator against 3.12/3.13/3.14 |
| `watcher.py` crashed with `NameError` when `watchdog` wasn't installed | `class _Handler(FileSystemEventHandler):` sat unconditionally at module scope — Python evaluates base classes immediately, so the surrounding `try/except ImportError` never actually protected against a missing import | Class definition wrapped in `if _WATCHDOG:`; verified directly (not just compiled) with watchdog both present and absent |

---

## 18. Glossary of Internal Terms

**Shield Score** — 0–100 health metric, unchanged formula.

**Active threat** — a scan result not yet `vt_cleared`.

**VT-cleared** — a result whose waterfall verdict was `"clean"` (from VirusTotal or a valid signature). Capped to `VT_CLEARED_SCORE_CAP`, shown in "Verified safe."

**NEW — Inconclusive / "unknown" verdict** — checked against every hash-based source and (on Windows) a digital signature, with nothing conclusive either way. Capped to `INCONCLUSIVE_SCORE_CAP` but **not** cleared — stays visible in the active list, since this is weaker evidence than a genuine "clean."

**NEW — Waterfall (hash lookups)** — MalwareBazaar → OTX → VirusTotal → signature check, stopping at the first definitive answer. Contrast with...

**NEW — Merge (IP/network lookups)** — AbuseIPDB + URLhaus + VirusTotal are all checked and the *worst* verdict wins; no waterfall short-circuiting, since reputation checks are cheap.

**NEW — Cross-scan file memory / "cleared once"** — a file that passed a scan clean is skipped on future scans (fast `os.stat()` check against `cleared_files`, keyed by path+mtime+size) until it actually changes. Invalidated wholesale after a YARA rules update.

**NEW — Actionable YARA match** — a match on a rule whose metadata doesn't mark it purely informational (`category != "info"`, `score >= 40`). Only actionable matches count toward threat scoring; all matches are still visible in details.

**YARA-Forge Extended** — the primary YARA rule source: ~10,700 curated, quality-filtered rules aggregated upstream from ReversingLabs/Neo23x0/others, fetched live with a vendored offline fallback.

**Quick Scan** — temp/download/desktop/document directories (depth 4) + network connections + startup items. The **only** scan type that includes network findings, and therefore the only one that can exercise AbuseIPDB/URLhaus.

**Deep Scan** — full filesystem walk (depth 64, cap 10,000 files). Files only — no network/startup findings.

**Custom Scan** — REST-based scan of a specific path with configurable file cap and extension filter. Files only.

**Digital signature check** — Windows Authenticode verification via PowerShell, used as the last resort when no hash database has ever seen a file. A validly-signed file is treated as clean even with zero database hits.

**Force full re-scan** — a per-scan toggle that bypasses the cross-scan file memory, checking every file fresh regardless of prior history.

**Heuristic score** — local file risk score (entropy, location, signatures, macros). Separate from YARA and threat-intel scoring; zeroed outright for known Microsoft system files.

**MITRE ATT&CK enrichment** — unchanged: automatic mapping of finding strings to ATT&CK technique IDs.

**Telemetry** — the 1-second WebSocket stream of CPU, memory, processes, and network data.

**Sidecar** — the Python backend process spawned by the Tauri desktop wrapper in production builds.

---

*This document reflects the codebase as of v2.3.0, incorporating the original architecture plus every fix and addition made across the project's Phase 1 (multi-provider threat intelligence), dependency-audit, and follow-up (attribution/observability/signature-fallback/scan-memory/install-blocking-bug) passes.*
