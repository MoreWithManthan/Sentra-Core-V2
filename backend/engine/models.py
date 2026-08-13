"""SENTRA CORE — Pydantic models v2.3"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── Existing ──────────────────────────────────────────────────────────────────

class ProcessInfo(BaseModel):
    name: str
    cpu_percent: float = Field(..., ge=0)


class StatsEntry(BaseModel):
    time: str
    cpu: float = Field(..., ge=0, le=100)
    memory: float = Field(default=0, ge=0, le=100)


class ScanResult(BaseModel):
    # Unique per-result identifier assigned at scan time. Bug fix: the
    # frontend previously matched live VirusTotal results back to threat
    # rows by filename, which meant two different files sharing a name
    # would incorrectly inherit each other's verdict. This id is the new
    # identification criteria — stable and unique regardless of filename.
    id: Optional[str] = None
    file: str
    risk_score: int = Field(..., ge=0, le=100)
    details: List[str]
    mitre_id: Optional[str] = None
    mitre_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    vt_checked: Optional[bool] = False
    vt_verdict: Optional[str] = None
    # Which provider produced vt_verdict (e.g. "malwarebazaar", "otx",
    # "virustotal", or "multi-source" for network findings).
    vt_source: Optional[str] = None
    vt_cleared: Optional[bool] = False


class CleanupRequest(BaseModel):
    deep_clean: bool = False


class CleanupResult(BaseModel):
    deleted_files: int = 0
    errors:        int = 0
    dns_reset:     bool = False
    sfc_output:    str = ""
    dism_output:   str = ""
    message:       str = ""


class IntelligenceUpdate(BaseModel):
    status:         str
    message:        str
    rules_updated:  Optional[int] = None
    sources_ok:     Optional[int] = None
    sources_failed: Optional[int] = None
    timestamp:      str
    path:           Optional[str] = None


class IntelMetadata(BaseModel):
    exists:      bool
    rules_count: Optional[int]  = None
    size_bytes:  Optional[int]  = None
    modified:    Optional[str]  = None
    sha256:      Optional[str]  = None


# ── Scan ──────────────────────────────────────────────────────────────────────

class CustomScanRequest(BaseModel):
    path: str
    recursive: bool = True
    max_files: int = Field(default=500, ge=1, le=5000)
    include_extensions: Optional[List[str]] = None


class CustomScanResponse(BaseModel):
    status:        str
    scan_type:     str = "custom"
    path_scanned:  str
    files_scanned: int
    threats_found: int
    shield_score:  int
    results:       List[ScanResult]
    timestamp:     str
    duration_sec:  float = 0
    truncated:     bool  = False


# ── VirusTotal ────────────────────────────────────────────────────────────────

class VTScanRequest(BaseModel):
    file_path:      str
    upload_unknown: bool = False


class VTScanResult(BaseModel):
    status:           str
    file_name:        Optional[str] = None
    sha256:           Optional[str] = None
    verdict:          Optional[str] = None
    detections:       Optional[int] = None
    malicious:        Optional[int] = None
    suspicious:       Optional[int] = None
    total_engines:    Optional[int] = None
    engines:          Optional[List[str]] = None
    permalink:        Optional[str] = None
    message:          Optional[str] = None
    from_cache:       Optional[bool] = None
    last_analysis_date: Optional[int] = None
    meaningful_name:  Optional[str] = None


class VTBatchRequest(BaseModel):
    file_paths:     List[str] = Field(..., min_length=1, max_length=50)
    upload_unknown: bool = False


class IPReputationRequest(BaseModel):
    ip: str


class StartupVTCheckRequest(BaseModel):
    path: str


class VTUsageStatus(BaseModel):
    configured:       bool
    cache_entries:    int = 0
    requests_made:    int
    cache_hits:       int
    last_request_at:  Optional[str] = None
    last_result:       Optional[str] = None
    session_started:  str


class VTKeyRequest(BaseModel):
    api_key: str


# ── Multi-source threat intelligence ─────────────────────────────────────────

class ProviderKeyRequest(BaseModel):
    """Generic key-setter for any keyed provider (OTX, AbuseIPDB, ...)."""
    provider: str
    api_key:  str


class ProviderUsage(BaseModel):
    """Session-scoped call count for one provider — resets on backend restart."""
    requests_made:    int = 0
    last_request_at:  Optional[str] = None
    last_result:      Optional[str] = None


class ThreatIntelStatus(BaseModel):
    # MalwareBazaar and URLhaus need no key and are always available.
    malwarebazaar_active:  bool = True
    urlhaus_active:        bool = True
    otx_configured:        bool = False
    abuseipdb_configured:  bool = False
    virustotal_configured: bool = False
    malwarebazaar_usage:   ProviderUsage = Field(default_factory=ProviderUsage)
    otx_usage:             ProviderUsage = Field(default_factory=ProviderUsage)
    abuseipdb_usage:       ProviderUsage = Field(default_factory=ProviderUsage)
    urlhaus_usage:         ProviderUsage = Field(default_factory=ProviderUsage)


class IPReputationResult(BaseModel):
    status:          str
    ip:              str
    verdict:         Optional[str] = None
    sources:         Optional[Dict[str, Any]] = None
    checked_sources: Optional[List[str]] = None


# ── Drives / system ───────────────────────────────────────────────────────────

class DriveInfo(BaseModel):
    device:       str
    mountpoint:   str
    fstype:       str
    total_gb:     float
    used_gb:      float
    free_gb:      float
    percent_used: float


class DrivesResponse(BaseModel):
    status: str
    drives: List[DriveInfo]


# ── Defender ──────────────────────────────────────────────────────────────────

class DefenderExclusionRequest(BaseModel):
    path: str


class DefenderExclusionResponse(BaseModel):
    status:  str
    message: str
    path:    Optional[str] = None


# ── Schedule ──────────────────────────────────────────────────────────────────

class ScheduleConfig(BaseModel):
    enabled:   bool = False
    scan_type: str  = "quick"
    frequency: str  = "daily"
    hour:      int  = Field(default=2, ge=0, le=23)
    minute:    int  = Field(default=0,  ge=0, le=59)


# ── Watcher ───────────────────────────────────────────────────────────────────

class WatcherConfig(BaseModel):
    enabled:    bool      = False
    watch_dirs: List[str] = []


# ── Report ────────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    scan_id: Optional[int] = None


# ── System repair ─────────────────────────────────────────────────────────────

class RepairStatus(BaseModel):
    status:      str
    message:     str
    sfc_output:  Optional[str] = None
    dism_output: Optional[str] = None
