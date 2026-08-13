"""PDF scan report generator using ReportLab."""

import io
import logging
import os
import platform
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )
    _REPORTLAB = True
except ImportError:
    _REPORTLAB = False
    logger.info("reportlab not installed — PDF export disabled. pip install reportlab")

_CYAN   = colors.HexColor("#22d3ee") if _REPORTLAB else None
_DARK   = colors.HexColor("#0c1524") if _REPORTLAB else None
_DANGER = colors.HexColor("#f87171") if _REPORTLAB else None
_WARN   = colors.HexColor("#fbbf24") if _REPORTLAB else None
_SAFE   = colors.HexColor("#4ade80") if _REPORTLAB else None
_GREY   = colors.HexColor("#94a3b8") if _REPORTLAB else None

MAX_PDF_ROWS = 150

# Bug fix: this file used to hardcode "VirusTotal" in every label
# regardless of which provider actually produced the verdict — a leftover
# from before the multi-source waterfall (MalwareBazaar / OTX / VirusTotal
# / digital signature) existed. Every label below now reads the per-row
# `vt_source` field instead.
_SOURCE_LABELS = {
    "malwarebazaar": "MalwareBazaar",
    "otx": "AlienVault OTX",
    "virustotal": "VirusTotal",
    "signature": "Digital Signature",
    "multi-source": "Threat Intelligence",
}


def _source_label(r: Dict[str, Any]) -> str:
    return _SOURCE_LABELS.get(r.get("vt_source"), "Threat Intelligence")


def _verdict_color(score: int):
    if score > 75: return _DANGER
    if score > 50: return _WARN
    if score > 25: return colors.HexColor("#fb923c")
    return _SAFE


def _get_file_path(r: Dict[str, Any]) -> str:
    """Accepts either the `file` or `file_path` key, whichever is present."""
    return r.get("file") or r.get("file_path") or ""


def generate_pdf(scan_data: Dict[str, Any]) -> bytes:
    if not _REPORTLAB:
        raise RuntimeError("reportlab is not installed. Run: pip install reportlab")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    styles = getSampleStyleSheet()

    heading1 = ParagraphStyle("h1", parent=styles["Heading1"],
                               textColor=_CYAN, fontSize=18, spaceAfter=6)
    heading2 = ParagraphStyle("h2", parent=styles["Heading2"],
                               textColor=_DARK, fontSize=12, spaceBefore=12)
    body     = ParagraphStyle("body", parent=styles["Normal"],
                               fontSize=9, textColor=colors.HexColor("#334155"))

    story = []

    story.append(Paragraph("SENTRA CORE — Scan Report", heading1))
    story.append(HRFlowable(width="100%", thickness=1, color=_CYAN))
    story.append(Spacer(1, 0.3*cm))

    ts        = scan_data.get("timestamp", datetime.now().isoformat())
    scan_type = scan_data.get("scan_type", "unknown").upper()
    files     = scan_data.get("files_scanned", 0)
    threats   = scan_data.get("threats_found", 0)
    shield    = scan_data.get("shield_score", 100)
    duration  = scan_data.get("duration_sec", 0)

    summary_data = [
        ["Field",         "Value"],
        ["Report Date",   datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Scan Date",     ts[:19].replace("T", " ")],
        ["Scan Type",     scan_type],
        ["System",        platform.node()],
        ["OS",            f"{platform.system()} {platform.release()}"],
        ["Files Scanned", str(files)],
        ["Threats Found", str(threats)],
        ["Shield Score",  f"{shield}%"],
        ["Duration",      f"{duration:.2f}s"],
    ]

    t = Table(summary_data, colWidths=[5*cm, 12*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), _DARK),
        ("TEXTCOLOR",   (0, 0), (-1, 0), _CYAN),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING",     (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    results: List[Dict] = scan_data.get("results", [])
    active = [r for r in results if not r.get("vt_cleared")]
    cleared = [r for r in results if r.get("vt_cleared")]

    if active:
        story.append(Paragraph("Detected Threats", heading2))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_GREY))
        story.append(Spacer(1, 0.2*cm))

        sorted_results = sorted(active, key=lambda x: -x.get("risk_score", 0))
        shown = sorted_results[:MAX_PDF_ROWS]

        if len(sorted_results) > MAX_PDF_ROWS:
            story.append(Paragraph(
                f"Showing the top {MAX_PDF_ROWS} of {len(sorted_results)} detections, sorted by risk.",
                ParagraphStyle("note", parent=body, textColor=_GREY, fontSize=7),
            ))
            story.append(Spacer(1, 0.15*cm))

        # Column renamed from "VT" to "Verdict" — the check behind it is no
        # longer VirusTotal-only, and which provider answered is shown in
        # the "Verified Safe" section below where there's room for the name.
        threat_rows = [["#", "File", "Score", "MITRE", "Verdict", "Details"]]
        for i, r in enumerate(shown, 1):
            file_path = _get_file_path(r)
            fname     = os.path.basename(file_path) if file_path else "(unknown file)"
            score     = r.get("risk_score", 0)
            mitre     = r.get("mitre_id") or "—"
            vt_flag   = r.get("vt_verdict") if r.get("vt_checked") else "—"
            details   = "; ".join(r.get("details", []))[:100]
            threat_rows.append([str(i), fname, f"{score}%", mitre, vt_flag or "—", details])

        th = Table(threat_rows, colWidths=[0.7*cm, 4.6*cm, 1.3*cm, 1.6*cm, 1.8*cm, 6.8*cm])
        style_cmds = [
            ("BACKGROUND",  (0, 0), (-1, 0), _DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0), _CYAN),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
            ("GRID",        (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING",     (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fef9f0")]),
        ]
        for row_i, r in enumerate(shown, 1):
            style_cmds.append(("TEXTCOLOR", (2, row_i), (2, row_i), _verdict_color(r.get("risk_score", 0))))
            if r.get("vt_verdict") == "malicious":
                style_cmds.append(("TEXTCOLOR", (4, row_i), (4, row_i), _DANGER))
        th.setStyle(TableStyle(style_cmds))
        story.append(th)
    else:
        story.append(Paragraph("Detected Threats", heading2))
        story.append(Paragraph("No active threats. Anything flagged locally was verified clean by the threat-intelligence pipeline.", body)
                     if cleared else Paragraph("No threats detected in this scan.", body))

    if cleared:
        story.append(Spacer(1, 0.35*cm))
        story.append(Paragraph("Verified Safe (Multi-Source Threat Intelligence)", heading2))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_GREY))
        story.append(Spacer(1, 0.15*cm))
        cleared_rows = [["File", "Note"]]
        for r in cleared[:MAX_PDF_ROWS]:
            fname = os.path.basename(_get_file_path(r)) or "(unknown file)"
            cleared_rows.append([fname, f"Flagged locally, confirmed clean by {_source_label(r)}"])
        ct = Table(cleared_rows, colWidths=[6.0*cm, 11.0*cm])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _DARK),
            ("TEXTCOLOR",  (0, 0), (-1, 0), _CYAN),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 7.5),
            ("TEXTCOLOR",  (0, 1), (-1, -1), _SAFE),
            ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("PADDING",    (0, 0), (-1, -1), 4),
        ]))
        story.append(ct)

    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Recommended Actions", heading2))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_GREY))
    story.append(Spacer(1, 0.2*cm))

    if files == 0:
        recs = [
            "No files were actually scanned — this isn't a clean result, it's an empty one.",
            "If this was a Deep or Custom scan, try running the backend as Administrator; "
            "most system folders require elevation to read.",
        ]
    elif threats == 0:
        recs = ["System appears clean. Run scheduled scans to maintain protection."]
    elif shield >= 80:
        recs = ["Low-risk items found. Review flagged files and remove if unnecessary."]
    elif shield >= 60:
        recs = [
            "Moderate risk detected. Review flagged executables individually.",
            "Use the built-in reputation check on any file you're unsure about.",
            "Keep Windows Defender definitions up to date.",
        ]
    else:
        recs = [
            "High-risk items detected — review before running any flagged file.",
            "Cross-check flagged files with the built-in threat-intelligence sources if you haven't already.",
            "Consider a full Windows Defender scan for a second opinion.",
            "Review startup items for anything you don't recognize.",
        ]

    for rec in recs:
        story.append(Paragraph(f"• {rec}", body))
    story.append(Spacer(1, 0.8*cm))

    story.append(HRFlowable(width="100%", thickness=0.5, color=_GREY))
    story.append(Paragraph(
        "Generated by SENTRA CORE v2.3.0 — Advanced System Security & Optimization Engine",
        ParagraphStyle("footer", parent=body, textColor=_GREY, fontSize=7),
    ))

    doc.build(story)
    return buf.getvalue()
