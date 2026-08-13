"""
Windows Authenticode signature verification.

Provides an additional trust signal beyond hash-database lookups: a file
validly signed by a real certificate is far less likely to be malware than
an unsigned one, since code-signing certificates cost money and are
traceable — something most malware authors avoid. This is what actually
resolves the common case a hash database can't: a legitimate but obscure
vendor DLL/EXE that nobody has ever submitted to VirusTotal/MalwareBazaar/
OTX before ("not_found" everywhere), which heuristics still flag due to
entropy or file location.

Windows-only; returns "unavailable" gracefully on every other platform.
"""

import logging
import os
import platform
import subprocess
from typing import Any, Dict

logger = logging.getLogger(__name__)

_TIMEOUT = 15


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _extract_cn(subject: str) -> str:
    """Pull the CN= (Common Name) field out of a certificate subject string."""
    for part in subject.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip()
    return subject


def check_signature(file_path: str) -> Dict[str, Any]:
    """
    Returns:
        {"status": "valid",  "signer": "..."}                      — validly signed, trusted
        {"status": "not_signed"}                                     — no signature present
        {"status": "invalid", "signer": "...", "detail": "..."}      — signed but
                                                                        untrusted/expired/tampered
        {"status": "unavailable", "message": "..."}                  — couldn't check
                                                                        (non-Windows, PowerShell
                                                                        error, timeout)

    The file path is passed via an environment variable rather than being
    interpolated into the PowerShell command string, so a path containing
    quotes or other special characters can never break out of the intended
    command.
    """
    if not _is_windows():
        return {"status": "unavailable", "message": "Signature check is Windows-only."}

    try:
        script = (
            "$s = Get-AuthenticodeSignature -LiteralPath $env:SENTRA_SIG_CHECK_PATH; "
            "if ($s.SignerCertificate) { $subj = $s.SignerCertificate.Subject } else { $subj = '' }; "
            "Write-Output \"$($s.Status)|$subj\""
        )
        env = dict(os.environ)
        env["SENTRA_SIG_CHECK_PATH"] = file_path

        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=_TIMEOUT, env=env,
        )
        if result.returncode != 0:
            return {"status": "unavailable", "message": result.stderr.strip() or "PowerShell error"}

        output = result.stdout.strip()
        if "|" not in output:
            return {"status": "unavailable", "message": f"Unexpected output: {output!r}"}

        status_str, subject = output.split("|", 1)
        status_str = status_str.strip()
        signer = _extract_cn(subject.strip())

        if status_str == "Valid":
            return {"status": "valid", "signer": signer or "Unknown signer"}
        if status_str == "NotSigned":
            return {"status": "not_signed"}
        # HashMismatch, NotTrusted, NotSupportedFileFormat, Incompatible, UnknownError
        return {"status": "invalid", "signer": signer or "Unknown signer", "detail": status_str}

    except subprocess.TimeoutExpired:
        return {"status": "unavailable", "message": "Signature check timed out."}
    except Exception as exc:
        logger.debug("Signature check error for %s: %s", file_path, exc)
        return {"status": "unavailable", "message": str(exc)}
