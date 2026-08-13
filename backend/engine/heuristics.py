"""Heuristic analysis engine for SENTRA CORE."""

import base64
import math
import os
import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger(__name__)


def _b64(s: str) -> bytes:
    return base64.b64decode(s)


# Magic bytes for common executable formats. Kept for informational
# context in the details list; not scored on their own, since every file
# reaching this function was already filtered to an executable-type
# extension — "this is a PE file" carries no discriminating signal when
# that's already the starting condition.
_SIG_PE = _b64("TVqQAA==")
_SIG_ELF = _b64("f0VMRg==")
_SIG_MACHO = [_b64("vuz6zg=="), _b64("vuz6zw=="), _b64("zvr+7g=="), _b64("z/r+7g==")]

_SUSPICIOUS_STRINGS: Dict[bytes, str] = {
    _b64("V2luUkFS"): "Embedded RAR archive (self-extracting payload risk)",
}

# Direct-execution risk: entropy-based packing detection is meaningful
# for these, since plain code and scripts are naturally low-entropy
# unless obfuscated.
EXECUTABLE_EXTENSIONS = (
    ".exe", ".dll", ".sh", ".bat", ".cmd", ".scr", ".vbs", ".ps1",
    ".js", ".jse", ".wsf", ".hta", ".jar", ".msi", ".lnk", ".py",
)

# Container formats. These are compressed by design, so raw entropy is
# always high regardless of content and isn't a useful signal here.
ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img")

# Office formats. The "m" variants can carry macros, a known infection
# vector independent of entropy. All of these — including the modern
# non-macro .docx/.xlsx/.pptx — are zip containers under the hood, so
# entropy doesn't distinguish anything for any of them.
DOCUMENT_EXTENSIONS = (
    ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt",
    ".docx", ".xlsx", ".pptx",
)

SUSPICIOUS_EXTENSIONS = EXECUTABLE_EXTENSIONS + ARCHIVE_EXTENSIONS + DOCUMENT_EXTENSIONS

_TEMP_SEGMENTS = ("\\temp\\", "\\tmp\\", "\\cache\\", "/temp/", "/tmp/", "/cache/")

# ---------------------------------------------------------------------------
# Known-legitimate Windows system files (Bug fix: Microsoft DLLs flagged as
# suspicious). This is a location + filename allowlist, not a full
# Authenticode signature check — it targets the specific complaint (core
# system DLLs under System32/SysWOW64/WinSxS being penalized by the
# temp-dir / entropy heuristics) without adding a Windows API dependency.
# A file only qualifies if BOTH the name is a known core DLL AND it's
# actually sitting in a genuine system directory — an identically-named
# file dropped somewhere else is still analyzed normally.
# ---------------------------------------------------------------------------
_MS_SYSTEM_DIR_MARKERS = ("system32", "syswow64", "winsxs")

_MS_KNOWN_SAFE_NAMES = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
    "advapi32.dll", "ole32.dll", "oleaut32.dll", "shell32.dll", "shlwapi.dll",
    "msvcrt.dll", "ucrtbase.dll", "combase.dll", "rpcrt4.dll", "sechost.dll",
    "wintrust.dll", "crypt32.dll", "bcrypt.dll", "bcryptprimitives.dll",
    "setupapi.dll", "winhttp.dll", "ws2_32.dll", "wininet.dll", "ntoskrnl.exe",
}


def _is_known_microsoft_system_file(file_path: str) -> bool:
    """
    Core Windows system DLLs sitting in System32/SysWOW64/WinSxS are
    legitimate by construction — flagging them wastes attention on false
    positives instead of real threats.
    """
    lower = file_path.lower().replace("/", "\\")
    name = os.path.basename(lower)
    in_system_dir = any(f"\\{marker}\\" in lower for marker in _MS_SYSTEM_DIR_MARKERS)
    return in_system_dir and name in _MS_KNOWN_SAFE_NAMES


def _category_for(ext: str) -> str:
    if ext in EXECUTABLE_EXTENSIONS:
        return "executable"
    if ext in ARCHIVE_EXTENSIONS:
        return "archive"
    if ext in DOCUMENT_EXTENSIONS:
        return "document"
    return "unknown"


def _in_temp_dir(file_path: str) -> bool:
    lower = file_path.lower()
    normalized = lower.replace("/", "\\")
    return any(seg in normalized or seg.replace("\\", "/") in lower for seg in _TEMP_SEGMENTS)


def calculate_entropy(file_path: str) -> float:
    """Shannon entropy of the first 10 KB. Above ~7.5 suggests packing or encryption."""
    try:
        with open(file_path, "rb") as fh:
            data = fh.read(10_000)
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy, n = 0.0, len(data)
        for count in freq:
            if count:
                p = count / n
                entropy -= p * math.log2(p)
        return entropy
    except Exception as exc:
        logger.warning("Entropy error for %s: %s", file_path, exc)
        return 0.0


def check_suspicious_sections(file_path: str) -> List[str]:
    findings: List[str] = []
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(8)
        if header[:4] == _SIG_PE:
            findings.append("Windows PE executable")
        elif header[:4] == _SIG_ELF:
            findings.append("ELF executable")
        elif header[:4] in _SIG_MACHO:
            findings.append("Mach-O executable")
    except Exception as exc:
        logger.warning("Section check error: %s", exc)
    return findings


def check_file_signatures(file_path: str) -> List[str]:
    findings: List[str] = []
    try:
        with open(file_path, "rb") as fh:
            header = fh.read(512)
        for sig, label in _SUSPICIOUS_STRINGS.items():
            if sig in header:
                findings.append(label)
    except Exception as exc:
        logger.warning("Signature check error: %s", exc)
    return findings


def _analyze_executable(file_path: str, file_size: int, in_temp: bool) -> Tuple[List[str], int]:
    findings: List[str] = []
    score = 0

    if file_size > 150 * 1024 * 1024:
        findings.append(f"Large file ({file_size / 1024 / 1024:.0f} MB)")
        score += 5

    entropy = calculate_entropy(file_path)
    if entropy > 7.5:
        findings.append(f"High entropy ({entropy:.2f}) — likely packed or encrypted payload")
        score += 35
    elif entropy > 7.0:
        findings.append(f"Elevated entropy ({entropy:.2f}) — possible compression")
        score += 15

    if in_temp:
        findings.append("Executable located in a temporary or cache directory")
        score += 35

    findings.extend(check_suspicious_sections(file_path))

    sig_hits = check_file_signatures(file_path)
    if sig_hits:
        findings.extend(sig_hits)
        score += 15

    return findings, score


def _analyze_archive(file_size: int, in_temp: bool) -> Tuple[List[str], int]:
    findings: List[str] = []
    score = 0

    if in_temp:
        findings.append("Archive located in a temporary or cache directory")
        score += 20

    if file_size > 500 * 1024 * 1024:
        findings.append(f"Large archive ({file_size / 1024 / 1024:.0f} MB)")
        score += 5

    return findings, score


def _analyze_document(file_path: str, in_temp: bool) -> Tuple[List[str], int]:
    findings: List[str] = []
    score = 0
    ext = os.path.splitext(file_path)[1].lower()

    if ext in (".docm", ".xlsm", ".pptm"):
        findings.append("Macro-enabled document")
        score += 15

    if in_temp:
        findings.append("Document located in a temporary or cache directory")
        score += 20

    return findings, score


def _analyze_unknown(in_temp: bool) -> Tuple[List[str], int]:
    """
    Extension isn't recognized as executable, archive, or document.
    Entropy analysis is only meaningful for the executable category, so
    an unrecognized type gets the same light-touch treatment as a
    document rather than defaulting to the more aggressive path.
    """
    findings: List[str] = []
    score = 0
    if in_temp:
        findings.append("File located in a temporary or cache directory")
        score += 20
    return findings, score


def analyze_file(file_path: str) -> Dict[str, Any]:
    """
    Multi-factor heuristic analysis of a single file. Returns
    {"findings": [...], "score": 0-100}.

    Scoring is category-specific: entropy analysis is only meaningful
    for raw executables and scripts, since archive and document
    containers are compressed by design and would otherwise flag on
    nearly every file of that type regardless of content. Known-legitimate
    Windows system files are excluded outright — see
    _is_known_microsoft_system_file.
    """
    try:
        if not os.path.isfile(file_path):
            return {"findings": ["File not found or not accessible"], "score": 0}

        if _is_known_microsoft_system_file(file_path):
            return {
                "findings": ["Recognized Windows system file — excluded from heuristic scoring"],
                "score": 0,
            }

        ext = os.path.splitext(file_path)[1].lower()
        category = _category_for(ext)
        file_size = os.path.getsize(file_path)
        in_temp = _in_temp_dir(file_path)

        if category == "archive":
            findings, score = _analyze_archive(file_size, in_temp)
        elif category == "document":
            findings, score = _analyze_document(file_path, in_temp)
        elif category == "executable":
            findings, score = _analyze_executable(file_path, file_size, in_temp)
        else:
            findings, score = _analyze_unknown(in_temp)

        return {"findings": findings, "score": min(score, 100)}

    except Exception as exc:
        logger.error("Analysis error for %s: %s", file_path, exc)
        return {"findings": [f"Analysis error: {exc}"], "score": 0}


def calculate_system_shield_score(scan_results: List[Dict[str, Any]]) -> int:
    """Convert aggregated threat data into a 0-100 health percentage."""
    if not scan_results:
        return 100
    try:
        max_risk = max(r.get("risk_score", 0) for r in scan_results)
        avg_risk = sum(r.get("risk_score", 0) for r in scan_results) / len(scan_results)
        combined = (0.7 * max_risk) + (0.3 * avg_risk)
        return max(0, int(100 - combined))
    except Exception as exc:
        logger.error("Shield score error: %s", exc)
        return 100
