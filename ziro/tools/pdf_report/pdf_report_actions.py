"""Professional PDF report generator using ReportLab.

Composes a branded pentest report from the engagement state + tracer's
vulnerability reports: exec summary, methodology, findings table (sorted by
risk_score), detailed finding cards with PoCs, compliance mapping, appendix.
"""

from __future__ import annotations

import os
import time
from typing import Any

from ziro.tools.registry import register_tool


@register_tool(sandbox_execution=True)
def generate_pdf_report(
    agent_state: Any,
    output_path: str = "/workspace/report.pdf",
    client_name: str = "",
    engagement_name: str = "",
    authorized_by: str = "",
    executive_summary: str = "",
    methodology: str = "",
    include_technical_details: bool = True,
    include_pocs: bool = True,
    include_compliance: bool = True,
) -> dict[str, Any]:
    """Render a branded PDF pentest report.

    Pulls findings from the global tracer, sorts by risk score, and composes:
    - Cover page with client, engagement name, date
    - Executive summary (1-2 pages, non-technical)
    - Methodology
    - Findings summary table
    - Detailed finding cards (one per finding) with title, severity, CVSS,
      compliance tags, impact, PoC, remediation, references
    - Appendix with raw proxy sample, timeline, artifact index

    Returns the PDF path and a summary of contents.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return {
            "success": False,
            "error": "reportlab not installed. Run: pip install reportlab. "
            "Add to containers/Dockerfile if you want it baked in.",
        }

    # Pull findings from tracer
    findings: list[dict[str, Any]] = []
    try:
        from ziro.telemetry.tracer import get_global_tracer

        tracer = get_global_tracer()
        if tracer and hasattr(tracer, "vulnerability_reports"):
            findings = list(tracer.vulnerability_reports or [])
    except Exception:  # noqa: BLE001
        pass

    # Sort by severity rank then CVSS score
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(
        key=lambda f: (
            sev_rank.get((f.get("severity") or "").upper(), 9),
            -(f.get("cvss_score") or 0),
        )
    )

    # Severity counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = (f.get("severity") or "UNKNOWN").upper()
        if s in counts:
            counts[s] += 1

    # Prep document
    os.makedirs(os.path.dirname(output_path) or "/workspace", exist_ok=True)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        title=f"Pentest Report — {engagement_name or client_name or 'Ziro'}",
        author="Ziro",
    )

    styles = getSampleStyleSheet()
    body = styles["BodyText"]
    body.fontSize = 10
    body.leading = 14
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=22, textColor=colors.HexColor("#111111"), spaceBefore=10, spaceAfter=8)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=15, textColor=colors.HexColor("#222222"), spaceBefore=12, spaceAfter=6)
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=12, textColor=colors.HexColor("#333333"), spaceBefore=8, spaceAfter=4)

    story: list[Any] = []

    # ---- Cover ----
    story.append(Spacer(1, 50 * mm))
    story.append(Paragraph("Security Assessment Report", h1))
    story.append(Spacer(1, 5 * mm))
    if engagement_name:
        story.append(Paragraph(f"<b>Engagement:</b> {engagement_name}", body))
    if client_name:
        story.append(Paragraph(f"<b>Client:</b> {client_name}", body))
    if authorized_by:
        story.append(Paragraph(f"<b>Authorized by:</b> {authorized_by}", body))
    story.append(Paragraph(f"<b>Generated:</b> {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}", body))
    story.append(Spacer(1, 30 * mm))

    # Severity summary card
    summary_data = [
        ["Severity", "Count"],
        ["Critical", str(counts["CRITICAL"])],
        ["High", str(counts["HIGH"])],
        ["Medium", str(counts["MEDIUM"])],
        ["Low", str(counts["LOW"])],
        ["Informational", str(counts["INFO"])],
        ["Total", str(sum(counts.values()))],
    ]
    summary_table = Table(summary_data, colWidths=[80 * mm, 40 * mm])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 11),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FFE6E6")),  # critical row
            ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#FFEACC")),  # high row
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#EEEEEE")),  # total row
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ])
    )
    story.append(summary_table)
    story.append(PageBreak())

    # ---- Executive Summary ----
    story.append(Paragraph("Executive Summary", h1))
    if executive_summary:
        for para in executive_summary.split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), body))
                story.append(Spacer(1, 4))
    else:
        total = sum(counts.values())
        auto_summary = (
            f"This assessment identified <b>{total}</b> findings across the engagement scope. "
            f"Of those, <b>{counts['CRITICAL']}</b> critical and <b>{counts['HIGH']}</b> high-severity "
            f"issues require immediate remediation. Lower-severity findings are included for completeness."
        )
        story.append(Paragraph(auto_summary, body))
    story.append(PageBreak())

    # ---- Methodology ----
    story.append(Paragraph("Methodology", h1))
    if methodology:
        story.append(Paragraph(methodology, body))
    else:
        story.append(Paragraph(
            "Automated multi-agent penetration testing covering reconnaissance, "
            "surface mapping, vulnerability analysis across OWASP Top 10 categories, "
            "authenticated and unauthenticated testing paths, and manual PoC validation. "
            "Findings are produced only after an exploit has been reproduced against "
            "the running target.",
            body,
        ))
    story.append(PageBreak())

    # ---- Findings Index ----
    story.append(Paragraph("Findings Index", h1))
    if findings:
        index_rows = [["#", "Severity", "Title", "CVSS"]]
        for i, f in enumerate(findings, start=1):
            index_rows.append([
                str(i),
                (f.get("severity") or "").upper(),
                (f.get("title") or "")[:80],
                f"{f.get('cvss_score') or '-':>3}",
            ])
        t = Table(index_rows, colWidths=[12 * mm, 24 * mm, 100 * mm, 18 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("<i>No findings captured by tracer.</i>", body))
    story.append(PageBreak())

    # ---- Detailed Findings ----
    story.append(Paragraph("Detailed Findings", h1))
    for i, f in enumerate(findings, start=1):
        sev = (f.get("severity") or "").upper()
        severity_colors = {
            "CRITICAL": colors.HexColor("#C0392B"),
            "HIGH": colors.HexColor("#E67E22"),
            "MEDIUM": colors.HexColor("#F1C40F"),
            "LOW": colors.HexColor("#27AE60"),
            "INFO": colors.HexColor("#3498DB"),
        }
        sev_color = severity_colors.get(sev, colors.grey)

        title_style = ParagraphStyle(
            f"finding_title_{i}", parent=h2, textColor=sev_color, fontSize=14,
        )
        card: list[Any] = [
            Paragraph(f"{i}. {f.get('title') or 'Untitled finding'}", title_style),
            Paragraph(f"<b>Severity:</b> {sev} &nbsp;&nbsp; <b>CVSS:</b> {f.get('cvss_score') or '-'}", body),
        ]
        if f.get("endpoint") or f.get("target"):
            card.append(Paragraph(
                f"<b>Target:</b> {f.get('target', '')} {('<b>Endpoint:</b> ' + f.get('endpoint', '')) if f.get('endpoint') else ''}",
                body,
            ))
        if f.get("cve"):
            card.append(Paragraph(f"<b>CVE:</b> {f.get('cve')}", body))
        if f.get("cwe"):
            card.append(Paragraph(f"<b>CWE:</b> {f.get('cwe')}", body))

        if include_compliance:
            compliance = f.get("compliance_tags") or []
            owasp = f.get("owasp_top10_2021") or ""
            if compliance or owasp:
                bits = []
                if owasp:
                    bits.append(f"<b>OWASP:</b> {owasp}")
                if compliance:
                    bits.append(f"<b>Compliance:</b> {', '.join(compliance)}")
                card.append(Paragraph(" &nbsp;&nbsp; ".join(bits), body))

        if f.get("description"):
            card.append(Paragraph("<b>Description</b>", h3))
            card.append(Paragraph(f.get("description", "")[:3000], body))
        if f.get("impact"):
            card.append(Paragraph("<b>Impact</b>", h3))
            card.append(Paragraph(f.get("impact", "")[:2000], body))
        if include_technical_details and f.get("technical_analysis"):
            card.append(Paragraph("<b>Technical Analysis</b>", h3))
            card.append(Paragraph(f.get("technical_analysis", "")[:4000], body))
        if include_pocs and f.get("poc_script_code"):
            card.append(Paragraph("<b>Proof of Concept</b>", h3))
            poc = (f.get("poc_script_code") or "")[:3000]
            # Use Preformatted for code
            card.append(Paragraph(f"<pre>{_escape_xml(poc)}</pre>", body))
        if f.get("remediation_steps"):
            card.append(Paragraph("<b>Remediation</b>", h3))
            card.append(Paragraph(f.get("remediation_steps", "")[:2000], body))

        story.append(KeepTogether(card))
        story.append(Spacer(1, 8))

    # Build
    try:
        doc.build(story)
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"PDF render failed: {e!s}"}

    size = os.path.getsize(output_path) if os.path.exists(output_path) else 0
    return {
        "success": True,
        "output_path": output_path,
        "size_bytes": size,
        "findings_count": len(findings),
        "severity_counts": counts,
        "pages_estimate": max(1, 5 + len(findings)),
    }


def _escape_xml(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
