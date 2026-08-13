<div align="center">

# 🛡️ Sentra Core

**Cross-platform cybersecurity dashboard and system optimizer**

*Multi-source threat intelligence · Real-time telemetry · One-click remediation · Runs entirely on your own machine*

[![Python](https://img.shields.io/badge/Python-3.10–3.13-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3-61DAFB?style=flat-square&logo=react&logoColor=black)](https://react.dev)
[![Tauri](https://img.shields.io/badge/Tauri-2.0-FFC131?style=flat-square&logo=tauri&logoColor=black)](https://tauri.app)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docs.docker.com/compose)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](#license)
[![Version](https://img.shields.io/badge/Version-2.3.0-0D9488?style=flat-square)](#)

</div>

---

## What is Sentra Core?

Sentra Core is a **local-first** cybersecurity and maintenance platform. It runs on your own machine (or your own server), keeps your files on your own disk, and hands you a real-time view of threats, processes, and network connections — without relying on any single vendor or cloud service.

**The detection philosophy is defence-in-depth at the intelligence layer.** Every suspicious file is waterfall-checked through five independent sources before a verdict is declared. A suspicious `.exe` in a temp folder doesn't just get a VirusTotal score — it runs through MalwareBazaar, AlienVault OTX, VirusTotal, and finally Windows Authenticode signature verification if nothing else resolves it.

**It is not a cloud SaaS product.** No file content ever leaves your machine. Only SHA-256 hashes are sent to external APIs, never raw bytes.

> Built as a research and engineering project under the guidance and feedback of **Mr. Johnny Krogsboll** — with a real use case in mind: making cybersecurity accessible to people who don't know what a threat actor is.

---

## ✨ Key Features

### 🔍 Multi-Source Threat Intelligence
- **5 independent sources** — VirusTotal (70+ AV engines), MalwareBazaar, AlienVault OTX, AbuseIPDB, URLhaus
- **Waterfall logic** — short-circuits on the first definitive answer; only falls through to the next source when inconclusive
- **Authenticode fallback** — for files none of the hash databases have ever seen, Windows digital signature verification provides a final verdict
- **24-hour local cache** — shared across all providers; avoids redundant API calls across scan sessions

### 📁 Intelligent File Scanning
- **Three scan modes** — Quick (2,000 files, hot dirs), Deep (25,000 files, full drive), Custom (user-defined path + cap + extension filter)
- **Priority-based file selection** — instead of stopping at the first N files alphabetically, scores every candidate by extension risk, location (temp/downloads), and recency. Scripts and executables always beat DLLs for scan budget
- **Cross-scan memory** — files confirmed clean are remembered by path + mtime + size. The next scan skips them instantly (one `stat()` call) until they change on disk. Entire cache is invalidated automatically after a YARA rules update
- **10,735 YARA rules** — YARA-Forge Extended bundle, vendored as an offline fallback so the app never starts with zero rules

### 📊 Real-Time Dashboard
- **1-second telemetry** over WebSocket — CPU, memory, top-12 processes, all active network connections
- **Shield Score (0–100)** — weighted formula using the max and average risk scores of active threats
- **Live threat feed** — threats stream to the UI as they are found; no waiting for the scan to finish
- **Process monitor** with CPU bar gauges
- **4 UI themes** — Cyan, Amber, Violet, Green; persisted to `localStorage`

### 🌐 Network & Startup Visibility
- **Network monitor** — all active connections, suspicious port flagging, one-click multi-source IP reputation check (AbuseIPDB + URLhaus + VirusTotal combined)
- **Startup scanner** — Windows registry `Run` / `RunOnce` keys (HKCU + HKLM) and the Startup folder; one-click reputation check per entry
- **MITRE ATT&CK attribution** — every confirmed threat is mapped to a technique ID (T1027, T1059, T1547, and 17 others)

### 🧹 One-Click Remediation
- Temp file purge (user + system)
- DNS resolver cache flush
- Windows component store cleanup (`DISM /Online /Cleanup-Image /StartComponentCleanup`)
- SFC system file repair (`sfc /scannow`)
- Platform-specific deep clean (APT autoremove on Linux; cache purge on macOS)

### 📄 Audit Reports
- Downloadable **PDF scan reports** via ReportLab — per-provider source attribution on every threat row, up to 150 rows
- Full **scan history** in SQLite — browse any past scan and re-download its report

### ⏰ Automation
- **Scheduled scans** — cron-based (daily / weekly / monthly) via APScheduler
- **Filesystem watchdog** — auto-scan any newly created executable in configured directories

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  BROWSER / TAURI WINDOW                 │
│                                                         │
│   React SPA ─── REST /api/* ────────────────────────►  │
│                ─── WebSocket /ws/telemetry ──────────►  │
│                ─── WebSocket /ws/scan ───────────────►  │
└─────────────────────────────────────────────────────────┘
                           │
┌─────────────────────────────────────────────────────────┐
│             FastAPI BACKEND  (port 8000)                │
│                                                         │
│  Engines:  heuristics → yara_scanner → mitre_mapper    │
│            → threat_intel waterfall:                    │
│              MalwareBazaar → OTX → VirusTotal          │
│              → Authenticode signature                   │
│            → network_monitor → startup_scanner         │
│            → system_optimize → report_generator        │
│                                                         │
│  SQLite:  scans · threats · vt_cache ·                 │
│           cleared_files · schedule_cfg · app_settings  │
│                                                         │
│  YARA rules:  yara_forge_extended.yar (10,735 rules)   │
└─────────────────────────────────────────────────────────┘
```

**Two WebSocket connections with distinct purposes:**
- `/ws/telemetry` — 1-second loop for live dashboard data; also doubles as a broadcast channel for background task completion events (scheduled scan done, rules update done, watchdog alert)
- `/ws/scan` — one session per scan; the backend streams threats as they are found, then closes the connection

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend runtime** | Python 3.10–3.13 |
| **API framework** | FastAPI 0.115+ · Uvicorn |
| **Threat intel clients** | requests 2.32+ (5 provider integrations) |
| **File analysis** | yara-python 4.5+ · psutil 6+ · ReportLab 4.2+ |
| **Persistence** | SQLite (WAL mode, raw `sqlite3`, no ORM) |
| **Scheduling** | APScheduler 3.10+ |
| **Filesystem events** | Watchdog 4.0+ |
| **Data validation** | Pydantic 2.9+ |
| **Frontend** | React 18.3 · Vite 5.4 |
| **Styling** | Tailwind CSS 3.4 |
| **Charts** | Recharts 3 · react-circular-progressbar |
| **Animations** | Framer Motion 12 |
| **Desktop wrapper** | Tauri 2.0 (Rust) |
| **Container** | Docker Compose · Kubernetes |
| **Web server** | Nginx 1.25 (reverse proxy + SPA) |

> **Dependency notes:** `yara-python` has no prebuilt wheel for Python 3.14 — the `requirements.txt` includes a `python_version < "3.14"` env marker so a `pip install` doesn't abort on 3.14. The full rationale for every pinned version floor is in [`DEPENDENCY_NOTES.md`](DEPENDENCY_NOTES.md).

---

## 🚀 Quick Start

### Prerequisites

| Tool | Minimum |
|---|---|
| Python | 3.10 |
| Node.js | 20 |
| Git | any |
| Docker + Docker Compose | Docker 24+ *(Docker mode only)* |
| Rust / Cargo stable | *(Tauri desktop mode only)* |

---

### Mode A — Local Development

```bash
# 1. Clone
git clone https://github.com/morewithmanthan/sentra-core-v2
cd sentra-core-v2

# 2. Configure
cp .env.example .env
# Edit .env — add API keys if you have them (all optional for basic scanning)

# 3. Backend
cd backend
pip install -r requirements.txt
python main.py
# → http://localhost:8000

# 4. Frontend (new terminal)
cd ..
npm install
npm run dev
# → http://localhost:5173
```

Open `http://localhost:5173`. The dashboard connects automatically. No further configuration is required for basic scanning.

---

### Mode B — Docker Compose

```bash
cp .env.example .env         # add API keys if desired
docker compose up --build

# Frontend → http://localhost:80
# Backend  → http://localhost:8000
```

---

### Mode C — Kubernetes

```bash
# Edit k8s/backend/secret.yaml with base64-encoded API keys before applying
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/backend/
kubectl apply -f k8s/frontend/ -f k8s/ingress.yaml -f k8s/hpa.yaml
```

> ⚠️ **Important:** Set `replicas: 1` in `k8s/backend/deployment.yaml`. The backend uses SQLite and there is no shared volume for the database — running two pods produces two diverging databases. See [Known Limitations](#known-limitations).

---

### Mode D — Tauri Desktop

```bash
npm install
npm run tauri dev
# Python backend must be running separately (see Mode A, step 3)
```

Release builds expect the Python backend as a compiled sidecar binary. See the Tauri documentation on `externalBin` for packaging.

---

## ⚙️ Configuration

All configuration is via environment variables (copy `.env.example` to `.env`):

| Variable | Default | Description |
|---|---|---|
| `API_HOST` | `127.0.0.1` | Backend bind address |
| `API_PORT` | `8000` | Backend listen port |
| `FRONTEND_URL` | `http://localhost:5173` | CORS allowed origin |
| `LOG_LEVEL` | `INFO` | Python logging verbosity |
| `DB_PATH` | `sentra.db` | SQLite database file path |
| `RULES_PATH` | `backend/engine/rules/active_threats.yar` | YARA rules file (generated at runtime) |
| `VT_API_KEY` | *(empty)* | VirusTotal v3 API key |
| `OTX_API_KEY` | *(empty)* | AlienVault OTX API key |
| `ABUSEIPDB_API_KEY` | *(empty)* | AbuseIPDB API key |
| `VITE_WS_URL` | `ws://localhost:8000` | WebSocket base URL for the frontend build |
| `VITE_API_TIMEOUT` | `30000` | API request timeout in milliseconds |

API keys can also be entered through the **Settings panel** in the UI — they are stored in SQLite and re-pushed to the backend automatically if it restarts.

**Which keys do what:**

| Source | Key required? | What it checks | When it fires |
|---|---|---|---|
| VirusTotal | Yes (free tier) | File hashes + IP reputation | All scan types + manual IP/startup checks |
| MalwareBazaar | No | File hashes | All scan types |
| AlienVault OTX | Yes (free, uncapped) | File hashes | All scan types |
| AbuseIPDB | Yes (free, 1k/day) | IP reputation | Quick Scan + manual network checks |
| URLhaus | No | IP/domain reputation | Quick Scan + manual network checks |

---

## 🔍 How Scanning Works

### Threat Intelligence Waterfall (per file)

```
SHA-256 hash
     │
     ▼
1. Shared cache hit? ──────────────────────────────► return cached result
     │ miss
     ▼
2. MalwareBazaar (no key, unlimited)
     │ "success" → malicious ────────────────────► confirmed malicious, cache & return
     │ not found / error → continue
     ▼
3. AlienVault OTX (free key)
     │ pulse found → malicious ──────────────────► confirmed malicious, cache & return
     │ not found ("no pulses" ≠ clean) → continue
     ▼
4. VirusTotal (free key, 70+ AV engines)
     │ clean ─────────────────────────────────────► confirmed clean, score capped to 5
     │ malicious / suspicious → return
     │ not found / no key → continue
     ▼
5. Authenticode signature check (Windows only)
     │ valid signature ────────────────────────────► confirmed clean
     │ not signed / invalid / unavailable
     ▼
   Verdict: INCONCLUSIVE — score capped to 15, stays visible in active threats
```

### Scoring

| Signal | Score |
|---|---|
| Entropy > 7.5 (packed/encrypted) | +35 pts *(executables only)* |
| Entropy 7.0–7.5 | +15 pts *(executables only)* |
| Located in temp or cache directory | +35 pts *(executables)* / +20 pts *(others)* |
| Embedded RAR signature | +15 pts |
| Macro-enabled document (`.docm`, `.xlsm`, `.pptm`) | +15 pts |
| Each actionable YARA rule match | +30 pts *(max 2 matches = +60)* |
| Known Microsoft system file (path + filename) | **Score forced to 0** |

Items scoring below **25** are not reported. Items that pass the waterfall as clean are recorded in a cross-scan memory cache (path + mtime + size) and skipped instantly on future scans until they change.

**Shield Score** = `max(0, 100 − (0.7 × max_risk + 0.3 × avg_risk_of_active_threats))`

---

## 🗺️ Roadmap

### Short Term (v3.0 target)

- [ ] Threat quarantine — move confirmed malicious files to an isolated directory
- [ ] One-click threat removal from the UI
- [ ] Windows Defender live status on the dashboard
- [ ] Email / SMS alert on scheduled scan findings
- [ ] PDF reports including network findings and startup items
- [ ] User-uploadable custom YARA rules
- [ ] Scan exclusion / allowlist (path or hash)
- [ ] Multi-language UI (Hindi and regional language support)
- [ ] Authentication on all API endpoints and WebSocket connections *(P0 security gap)*
- [ ] Automated test suite — regression tests for every bug in the [known-issue history](CHANGELOG.md)

### Long Term

- **Remote management** — a trusted family member triggers a scan or optimisation on a relative's PC from a mobile app; the remote machine executes and streams results back, requiring no action from the person at the machine
- **Parental controls** — DNS-based content filtering, per-application network rules, session time limits, and weekly domain-access summaries for parents
- **ClamAV integration** — additional AV engine alongside YARA
- **PostgreSQL / shared DB** — replace SQLite for multi-replica Kubernetes deployments
- **CI/CD pipeline** — GitHub Actions for `pytest`, `npm run build`, and Docker image build on every push

---

## ⚠️ Known Limitations

These are documented honestly — not to discourage use, but so you know exactly what the project's current boundaries are.

**Security gaps (before deploying anywhere beyond localhost):**
- **No authentication** on any REST endpoint or WebSocket connection. Every API is completely open. Do not expose the backend port to an untrusted network in its current state
- **No TLS** configured. Nginx config does not include HTTPS
- API keys (VT, OTX, AbuseIPDB) are stored as plaintext in SQLite
- FastAPI's interactive `/docs` and `/redoc` pages are live and unauthenticated
- `defender.py`'s PowerShell commands interpolate the path directly into the command string — a path containing `"` could break quoting. The injection-safe pattern (env-var pass-through) is already implemented in `signature_check.py` and needs to be retrofitted here

**Kubernetes:**
- `replicas: 2` in the backend deployment is incorrect for SQLite. Each pod gets its own diverging database. **Run with `replicas: 1`** until a shared database is implemented

**Engineering:**
- No automated tests — all verification has been manual
- No CI/CD pipeline
- No static analysis tooling (`ruff`, `mypy`, `eslint`)
- Frontend ships as a single ~715KB JS bundle (no code-splitting yet)
- Risk levels are communicated primarily through colour — accessibility gap for colour-blind users

**Scope:**
- Does not scan inside archives (archives are YARA-matched as opaque blobs, not extracted)
- AbuseIPDB and URLhaus only fire on Quick Scans and manual network checks — never on Deep or Custom scans (by design; those scan files, not network connections)
- Tauri sidecar binary must be compiled and bundled separately — not included in the repository

---

## 📁 Repository Structure

<details>
<summary>Click to expand full structure</summary>

```
sentra-core/
│
├── backend/
│   ├── main.py                  ← FastAPI app — 35+ REST endpoints, 2 WebSocket handlers
│   ├── database.py              ← SQLite persistence — 7 tables, WAL mode
│   ├── scheduler.py             ← APScheduler wrapper for scheduled scans
│   ├── watcher.py               ← Watchdog filesystem monitor
│   ├── requirements.txt
│   ├── pyproject.toml
│   └── engine/
│       ├── heuristics.py        ← Entropy, location, signature, macro analysis
│       ├── yara_scanner.py      ← YARA compile + severity-aware match filtering
│       ├── threat_intel.py      ← Multi-source orchestrator (waterfall + IP merge)
│       ├── virustotal.py        ← VT API v3 — rate limiting, caching, session stats
│       ├── malwarebazaar.py     ← MalwareBazaar client (no key required)
│       ├── otx.py               ← AlienVault OTX client
│       ├── abuseipdb.py         ← AbuseIPDB client (IP reputation)
│       ├── urlhaus.py           ← URLhaus client (IP/domain reputation)
│       ├── signature_check.py   ← Windows Authenticode via PowerShell (injection-safe)
│       ├── mitre_mapper.py      ← 20-technique ATT&CK keyword mapping
│       ├── network_monitor.py   ← psutil connections + suspicious port detection
│       ├── startup_scanner.py   ← Registry Run keys + Startup folder
│       ├── defender.py          ← Windows Defender exclusion management
│       ├── parallel_scanner.py  ← ThreadPoolExecutor(workers=6)
│       ├── system_optimize.py   ← Temp purge, DNS flush, DISM/SFC/apt/brew
│       ├── updater.py           ← YARA-Forge Extended fetch + supplementary rules
│       ├── report_generator.py  ← ReportLab PDF — dynamic per-provider attribution
│       ├── models.py            ← All Pydantic response models
│       └── rules/
│           ├── yara_forge_extended.yar  ← Vendored offline fallback (10,735 rules)
│           └── active_threats.yar       ← Generated at runtime (git-ignored)
│
├── src/
│   ├── App.jsx                  ← Root state, tab routing, theme system, WS event handling
│   ├── hooks/
│   │   ├── useWebSocket.js      ← useTelemetry() + useScanWS() — id-based vt_result matching
│   │   └── useApi.js
│   ├── services/api.js          ← req() wrapper — AbortController timeout, APIError class
│   └── components/
│       ├── TopNav.jsx           ← Navigation, theme switcher, action buttons
│       ├── ShieldGauge.jsx      ← Shield Score circular gauge
│       ├── SystemGraph.jsx      ← Recharts CPU + RAM area chart
│       ├── ThreatFeed.jsx       ← Live threat list with per-provider badges
│       ├── NetworkMonitor.jsx   ← Connection table + multi-source IP check
│       ├── StartupItems.jsx     ← Registry entries + reputation check
│       ├── ScanHistory.jsx      ← Past scans + PDF download
│       ├── SettingsPanel.jsx    ← API keys, live usage counters, schedule, watcher
│       ├── ScanModal.jsx        ← Scan type, verify toggle, force-rescan toggle
│       ├── CleanupModal.jsx     ← Cleanup option picker
│       └── ...                  ← Toast, Modal, ErrorBoundary, VTKeyModal, etc.
│
├── src-tauri/                   ← Tauri 2.0 — system tray, sidecar spawn, close-to-tray
├── k8s/                         ← Kubernetes manifests (namespace, HPA, Ingress, PVC, secrets)
├── docker/nginx.conf            ← /api proxy + SPA fallback + security headers
├── Dockerfile.backend           ← python:3.11-slim (within yara-python wheel range)
├── Dockerfile.frontend          ← node:20-alpine → build → nginx:1.25-alpine
├── docker-compose.yml
├── vite.config.js               ← esbuild minifier (not terser — terser is not installed)
├── .env.example
├── CHANGELOG.md
└── DEPENDENCY_NOTES.md
```

</details>

---

## 🖥️ Windows Administrator Mode

Some features require elevated privileges on Windows:

| Feature | Requires Admin? |
|---|---|
| Quick Scan (user temp dirs, downloads) | No |
| Network monitoring | No |
| Startup item enumeration | No |
| Deep / Custom Scan of system directories | **Yes** |
| Windows Defender exclusion management | **Yes** |
| SFC system file repair | **Yes** |
| DISM component cleanup | **Yes** |

Run the backend with `Run as Administrator` if you intend to use system-level scanning or repair features.

---

## 🤝 Contributing

The project is at an early stage with significant engineering gaps (no test suite, no CI). Contributions in any of these areas are especially welcome:

1. **Tests** — regression tests for the [bugs in the changelog](CHANGELOG.md) would turn a historical list into an enforced contract
2. **Authentication** — the P0 security gap; any approach (API keys, JWT, local session) is an improvement over the current zero-auth state
3. **Code splitting** — the frontend bundle is a single ~715KB file with a Rollup warning
4. **Accessibility** — risk levels need a non-colour redundant signal (text labels, icons) for colour-blind users

```bash
# Standard flow
git checkout -b feature/your-feature
# make your changes
git commit -m "feat: describe what changed"
git push origin feature/your-feature
# open a pull request
```

**Before touching scan logic**, read [`SENTRA_CORE_CODEBASE.md`](SENTRA_CORE_CODEBASE.md) — it documents the reasoning behind every non-obvious decision (e.g., why `useWebSocket.js` matches `vt_result` frames by `id` and not by filename, why `watcher.py`'s class definition must stay inside `if _WATCHDOG:`, why the yara-python env marker exists).

---

## 📜 License

MIT — see [`LICENSE`](LICENSE) for details.

The vendored YARA rules file (`backend/engine/rules/yara_forge_extended.yar`) is sourced from [YARA-Forge](https://github.com/YARAHQ/yara-forge) and is subject to its own licensing terms.

---

## 👤 Author

**Manthan Garg**
Chitkara University, CSOET — Solan, Himachal Pradesh, India

---

<div align="center">

*Sentra Core — because your PC deserves better than a slow machine and a missed threat.*

</div>
