import json
from datetime import datetime, timezone
from html import escape
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.models import Investigation, Target, Finding, Evidence, CollectionJob

def investigation_payload(db: Session, investigation_id: str) -> dict:
    inv = db.get(Investigation, investigation_id)
    if not inv: raise ValueError("Investigation not found")
    targets = db.scalars(select(Target).where(Target.investigation_id == inv.id)).all()
    findings = db.scalars(select(Finding).where(Finding.investigation_id == inv.id).order_by(Finding.collected_at.desc())).all()
    jobs = db.scalars(select(CollectionJob).where(CollectionJob.investigation_id == inv.id)).all()
    evidence_ids = [f.evidence_id for f in findings if f.evidence_id]
    evidence = db.scalars(select(Evidence).where(Evidence.id.in_(evidence_ids))).all() if evidence_ids else []
    ev_map = {e.id: e for e in evidence}
    return {
        "report_generated_at": datetime.now(timezone.utc).isoformat(),
        "investigation": {"id": inv.id, "name": inv.name, "description": inv.description, "status": inv.status, "created_at": inv.created_at.isoformat()},
        "targets": [{"id": t.id, "value": t.value, "type": t.target_type, "normalized_value": t.normalized_value} for t in targets],
        "jobs": [{"id": j.id, "status": j.status, "modules": j.modules, "findings_count": j.findings_count, "error": j.error} for j in jobs],
        "findings": [{"id": f.id, "target_id": f.target_id, "module": f.module, "type": f.finding_type, "value": f.value, "details": f.details, "source_url": f.source_url, "collected_at": f.collected_at.isoformat(), "confidence": f.confidence, "verification_status": f.verification_status, "evidence": ({"id": ev_map[f.evidence_id].id, "sha256": ev_map[f.evidence_id].sha256} if f.evidence_id in ev_map else None)} for f in findings],
    }

def render_html(payload: dict) -> str:
    inv = payload["investigation"]
    rows = []
    for f in payload["findings"]:
        source = f'<a href="{escape(f["source_url"])}" rel="noreferrer">Source</a>' if f.get("source_url") else "No external source"
        rows.append(f"<tr><td>{escape(f['module'])}</td><td>{escape(f['type'])}</td><td>{escape(str(f['value']))[:1200]}</td><td>{f['confidence']:.2f}</td><td>{source}</td><td>{escape(f['verification_status'])}</td></tr>")
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>{escape(inv['name'])} - Cyber X OSINT</title><style>body{{font-family:Arial,sans-serif;background:#f5f7fb;color:#172033;margin:32px}}h1{{color:#174ea6}}table{{border-collapse:collapse;width:100%;background:white}}th,td{{padding:10px;border:1px solid #d9e0ec;text-align:left;vertical-align:top}}th{{background:#e9effa}}.muted{{color:#5c667a}}</style></head><body><h1>Cyber X OSINT</h1><h2>{escape(inv['name'])}</h2><p class="muted">Generated: {escape(payload['report_generated_at'])}</p><p>{escape(inv.get('description') or '')}</p><h3>Targets</h3><ul>{''.join(f"<li>{escape(t['type'])}: {escape(t['value'])}</li>" for t in payload['targets'])}</ul><h3>Findings ({len(payload['findings'])})</h3><table><thead><tr><th>Module</th><th>Type</th><th>Finding</th><th>Confidence</th><th>Source</th><th>Status</th></tr></thead><tbody>{''.join(rows)}</tbody></table><p class="muted">Confidence is an analytical indicator, not proof. Verify source material independently.</p></body></html>'''

def render_pdf(payload: dict) -> bytes:
    from io import BytesIO
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from xml.sax.saxutils import escape as xml_escape

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4), rightMargin=14*mm, leftMargin=14*mm, topMargin=14*mm, bottomMargin=14*mm, title="Cyber X OSINT Investigation Report")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7, leading=9, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Muted", parent=styles["BodyText"], fontSize=8, textColor=colors.HexColor("#5d6b7d")))
    story = []
    inv = payload["investigation"]
    story.append(Paragraph("Cyber X OSINT", styles["Title"]))
    story.append(Paragraph(xml_escape(inv["name"]), styles["Heading1"]))
    story.append(Paragraph("Generated: " + xml_escape(payload["report_generated_at"]), styles["Muted"]))
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph("Investigation Summary", styles["Heading2"]))
    story.append(Paragraph(xml_escape(inv.get("description") or "No description supplied."), styles["BodyText"]))
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph("Targets", styles["Heading2"]))
    target_rows = [[Paragraph("Type", styles["SmallCell"]), Paragraph("Target", styles["SmallCell"])]]
    target_rows.extend([[Paragraph(xml_escape(t["type"]), styles["SmallCell"]), Paragraph(xml_escape(t["value"]), styles["SmallCell"])] for t in payload["targets"]])
    target_table = Table(target_rows, colWidths=[35*mm, 220*mm], repeatRows=1)
    target_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e8eef7")),("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#cbd5e1")),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),5)]))
    story.append(target_table); story.append(Spacer(1, 5*mm))
    story.append(Paragraph(f"Findings ({len(payload['findings'])})", styles["Heading2"]))
    rows = [[Paragraph(x, styles["SmallCell"]) for x in ["Module", "Type", "Observation", "Confidence", "Verification", "Source"]]]
    for finding in payload["findings"]:
        source = finding.get("source_url") or "Local / derived"
        rows.append([
            Paragraph(xml_escape(finding["module"]), styles["SmallCell"]),
            Paragraph(xml_escape(finding["type"]), styles["SmallCell"]),
            Paragraph(xml_escape(str(finding["value"])[:500]), styles["SmallCell"]),
            Paragraph(f"{finding['confidence']:.2f}", styles["SmallCell"]),
            Paragraph(xml_escape(finding["verification_status"]), styles["SmallCell"]),
            Paragraph(xml_escape(source[:180]), styles["SmallCell"]),
        ])
    finding_table = Table(rows, colWidths=[28*mm, 32*mm, 105*mm, 20*mm, 30*mm, 55*mm], repeatRows=1)
    finding_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#dbeafe")),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#cbd5e1")),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),4), ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f8fafc")])]))
    story.append(finding_table)
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph("Evidence and interpretation note", styles["Heading2"]))
    story.append(Paragraph("Evidence digests and source references are preserved in the investigation workspace. Confidence is an analytical indicator, not proof. Validate material findings against original sources. Credential values are deliberately excluded from exported reports.", styles["Muted"]))
    doc.build(story)
    return buffer.getvalue()
