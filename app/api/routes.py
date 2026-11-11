import json
import hashlib
import os
import uuid
from pathlib import Path
from fastapi import APIRouter, Depends, Header, HTTPException, BackgroundTasks, UploadFile, File, Form, Response, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models.models import Investigation, Target, CollectionJob, Finding, Evidence, Entity, Relationship, CredentialRecord, AuditLog, Source, ExposureDataset, ExposureIndicator, now_utc
from app.core.config import settings, STORAGE_DIR
from app.core.security import verify_api_token, encrypt_secret, decrypt_secret
from app.core.targets import detect_target, modules_for_target, MODULES
from app.services.collection import run_collection_job
from app.services.files import sha256_file, extract_file_metadata
from app.reporting.report import investigation_payload, render_html, render_pdf
from app.collectors.safety import normalize_http_url
from app.services.breach_intel import lookup_email_breaches, check_password_exposure
from app.services.authorized_database import configured_databases, public_database_catalog, count_exact_matches, AuthorizedDatabaseError
from app.services.exposure_datasets import parse_redacted_csv, identifier_hmac, DatasetValidationError, MAX_DATASET_BYTES

router = APIRouter(prefix="/api/v1")

class InvestigationIn(BaseModel):
    name: str = Field(min_length=2, max_length=180)
    description: str | None = Field(default=None, max_length=4000)

class TargetIn(BaseModel):
    value: str = Field(min_length=2, max_length=2048)
    target_type: str | None = None

class CollectIn(BaseModel):
    modules: list[str] | None = None

class CredentialIn(BaseModel):
    identifier_type: str = Field(pattern="^(email|username)$")
    identifier_reference: str = Field(min_length=2, max_length=512)
    password: str = Field(min_length=1, max_length=4096)
    authorization_context: str = Field(min_length=8, max_length=1000)
    target_id: str | None = None

class BreachCheckIn(BaseModel):
    authorization_context: str = Field(min_length=12, max_length=1000)

class PasswordExposureIn(BaseModel):
    password: str = Field(min_length=1, max_length=4096)
    authorization_context: str = Field(min_length=12, max_length=1000)
    target_id: str | None = None

class DatabaseLookupIn(BaseModel):
    connector_name: str = Field(min_length=2, max_length=64)
    table: str = Field(min_length=1, max_length=63)
    column: str = Field(min_length=1, max_length=63)
    target_id: str
    authorization_context: str = Field(min_length=12, max_length=1000)

class SourceIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    category: str = Field(min_length=2, max_length=60)
    source_url: str | None = Field(default=None, max_length=2000)
    description: str | None = Field(default=None, max_length=1000)

async def require_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None),
):
    token = x_api_token
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    if settings.api_token:
        if not verify_api_token(token):
            raise HTTPException(status_code=401, detail="Missing or invalid access token")
        return
    if os.getenv("VERCEL", "").lower() in {"1", "true", "yes"} or settings.app_env.lower() == "production":
        raise HTTPException(status_code=503, detail="Remote deployment is locked: configure API_TOKEN in the server environment")
    import ipaddress
    client_host = request.client.host if request.client else ""
    try:
        local_client = ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        local_client = False
    if not local_client:
        raise HTTPException(status_code=401, detail="Remote access requires API_TOKEN in the server environment")

def audit(db: Session, action: str, object_type: str, object_id: str | None = None, investigation_id: str | None = None, detail: str | None = None):
    db.add(AuditLog(action=action, object_type=object_type, object_id=object_id, investigation_id=investigation_id, detail=detail))

@router.get("/dashboard", dependencies=[Depends(require_auth)])
def dashboard(db: Session = Depends(get_db)):
    return {
        "investigations": db.scalar(select(func.count()).select_from(Investigation)) or 0,
        "targets": db.scalar(select(func.count()).select_from(Target)) or 0,
        "findings": db.scalar(select(func.count()).select_from(Finding)) or 0,
        "evidence": db.scalar(select(func.count()).select_from(Evidence)) or 0,
        "active_jobs": db.scalar(select(func.count()).select_from(CollectionJob).where(CollectionJob.status.in_(["queued", "running"]))) or 0,
        "completed_jobs": db.scalar(select(func.count()).select_from(CollectionJob).where(CollectionJob.status.in_(["completed", "partial"]))) or 0,
        "failed_jobs": db.scalar(select(func.count()).select_from(CollectionJob).where(CollectionJob.status == "failed")) or 0,
        "recent_findings": _finding_list(db, None, 8),
    }

def _finding_list(db: Session, investigation_id: str | None, limit: int = 100):
    stmt = select(Finding).order_by(Finding.collected_at.desc()).limit(limit)
    if investigation_id: stmt = stmt.where(Finding.investigation_id == investigation_id)
    rows = db.scalars(stmt).all()
    return [{"id": x.id, "investigation_id": x.investigation_id, "target_id": x.target_id, "module": x.module, "finding_type": x.finding_type, "value": x.value, "source_url": x.source_url, "collected_at": x.collected_at.isoformat(), "confidence": x.confidence, "verification_status": x.verification_status, "evidence_id": x.evidence_id} for x in rows]

@router.get("/modules", dependencies=[Depends(require_auth)])
def modules():
    labels = {"username":"Username Intelligence","email":"Email Intelligence","phone":"Phone Intelligence","domain":"Domain Intelligence","ip":"IP Intelligence","social":"Social Media Intelligence","image":"Image Intelligence","website":"Website Intelligence","credential":"Credential Intelligence","breach":"Breach Intelligence","threat":"Threat Intelligence","search":"Search Engine Intelligence","document":"Document Intelligence","github":"GitHub & Code Intelligence","network":"Network Intelligence","attack_surface":"Attack Surface Intelligence","digital_footprint":"Digital Footprint","correlation":"Intelligence Correlation"}
    return [{"id": m, "name": labels.get(m, m.replace("_", " ").title())} for m in MODULES]

@router.post("/investigations", dependencies=[Depends(require_auth)])
def create_investigation(payload: InvestigationIn, db: Session = Depends(get_db)):
    inv = Investigation(name=payload.name, description=payload.description)
    db.add(inv); db.flush(); audit(db, "investigation.created", "investigation", inv.id, inv.id); db.commit(); db.refresh(inv)
    return {"id": inv.id, "name": inv.name, "description": inv.description, "status": inv.status, "created_at": inv.created_at.isoformat()}

@router.get("/investigations", dependencies=[Depends(require_auth)])
def list_investigations(db: Session = Depends(get_db)):
    rows = db.scalars(select(Investigation).order_by(Investigation.updated_at.desc())).all()
    result = []
    for inv in rows:
        result.append({"id": inv.id, "name": inv.name, "description": inv.description, "status": inv.status,
                       "created_at": inv.created_at.isoformat(),
                       "target_count": db.scalar(select(func.count()).select_from(Target).where(Target.investigation_id == inv.id)) or 0,
                       "finding_count": db.scalar(select(func.count()).select_from(Finding).where(Finding.investigation_id == inv.id)) or 0})
    return result

@router.get("/investigations/{investigation_id}", dependencies=[Depends(require_auth)])
def get_investigation(investigation_id: str, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv: raise HTTPException(404, "Investigation not found")
    targets = db.scalars(select(Target).where(Target.investigation_id == inv.id)).all()
    jobs = db.scalars(select(CollectionJob).where(CollectionJob.investigation_id == inv.id).order_by(CollectionJob.started_at.desc())).all()
    return {"id": inv.id, "name": inv.name, "description": inv.description, "status": inv.status,
            "created_at": inv.created_at.isoformat(),
            "targets": [{"id": t.id, "value": t.value, "type": t.target_type, "normalized_value": t.normalized_value} for t in targets],
            "jobs": [{"id": j.id, "target_id": j.target_id, "modules": j.modules, "status": j.status, "findings_count": j.findings_count, "error": j.error, "started_at": j.started_at.isoformat() if j.started_at else None, "finished_at": j.finished_at.isoformat() if j.finished_at else None} for j in jobs],
            "findings": _finding_list(db, inv.id, 500)}

@router.post("/investigations/{investigation_id}/targets", dependencies=[Depends(require_auth)])
def add_target(investigation_id: str, payload: TargetIn, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv: raise HTTPException(404, "Investigation not found")
    try:
        detected_type, normalized = detect_target(payload.value)
        target_type = payload.target_type or detected_type
        if target_type not in {"email", "username", "phone", "domain", "url", "ip", "cidr", "file_hash", "name"}:
            raise ValueError("Unsupported target type")
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    existing = db.scalar(select(Target).where(Target.investigation_id == inv.id, Target.normalized_value == normalized, Target.target_type == target_type))
    if existing:
        return {"id": existing.id, "value": existing.value, "type": existing.target_type, "normalized_value": existing.normalized_value, "existing": True, "recommended_modules": modules_for_target(target_type)}
    target = Target(investigation_id=inv.id, value=payload.value, normalized_value=normalized, target_type=target_type)
    db.add(target); db.flush(); audit(db, "target.created", "target", target.id, inv.id, f"type={target_type}"); db.commit(); db.refresh(target)
    return {"id": target.id, "value": target.value, "type": target.target_type, "normalized_value": target.normalized_value, "existing": False, "recommended_modules": modules_for_target(target_type)}

@router.post("/investigations/{investigation_id}/bulk-targets", dependencies=[Depends(require_auth)])
def bulk_targets(investigation_id: str, values: list[str], db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv: raise HTTPException(404, "Investigation not found")
    if len(values) > 500: raise HTTPException(413, "Maximum 500 targets per import")
    added, skipped, errors = [], [], []
    for raw in values:
        try:
            kind, norm = detect_target(raw)
            old = db.scalar(select(Target).where(Target.investigation_id == inv.id, Target.normalized_value == norm, Target.target_type == kind))
            if old: skipped.append(raw); continue
            row = Target(investigation_id=inv.id, value=raw, normalized_value=norm, target_type=kind)
            db.add(row); db.flush(); added.append({"id": row.id, "value": row.value, "type": row.target_type})
        except Exception as exc:
            errors.append({"value": raw[:200], "error": str(exc)[:200]})
    audit(db, "targets.bulk_imported", "investigation", inv.id, inv.id, f"added={len(added)} skipped={len(skipped)} errors={len(errors)}")
    db.commit()
    return {"added": added, "skipped": skipped, "errors": errors}

@router.post("/investigations/{investigation_id}/targets/{target_id}/collect", dependencies=[Depends(require_auth)])
def collect_target(investigation_id: str, target_id: str, payload: CollectIn, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = db.get(Target, target_id)
    if not target or target.investigation_id != investigation_id: raise HTTPException(404, "Target not found in this investigation")
    requested = payload.modules or modules_for_target(target.target_type)
    modules_selected = list(dict.fromkeys(m for m in requested if m in MODULES and m not in {"credential", "image", "document"}))
    if not modules_selected: raise HTTPException(400, "Select at least one supported collection module")
    job = CollectionJob(investigation_id=investigation_id, target_id=target_id, modules=modules_selected, status="queued")
    db.add(job); db.flush(); audit(db, "collection.queued", "collection_job", job.id, investigation_id, f"modules={','.join(modules_selected)}"); db.commit(); db.refresh(job)
    background_tasks.add_task(run_collection_job, job.id)
    return {"job_id": job.id, "status": job.status, "modules": job.modules}

@router.get("/jobs/{job_id}", dependencies=[Depends(require_auth)])
def get_job(job_id: str, db: Session = Depends(get_db)):
    job = db.get(CollectionJob, job_id)
    if not job: raise HTTPException(404, "Job not found")
    return {"id": job.id, "status": job.status, "modules": job.modules, "findings_count": job.findings_count, "error": job.error,
            "started_at": job.started_at.isoformat() if job.started_at else None, "finished_at": job.finished_at.isoformat() if job.finished_at else None}

@router.get("/investigations/{investigation_id}/graph", dependencies=[Depends(require_auth)])
def get_graph(investigation_id: str, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv: raise HTTPException(404, "Investigation not found")
    entities = db.scalars(select(Entity).where(Entity.investigation_id == inv.id)).all()
    relations = db.scalars(select(Relationship).where(Relationship.investigation_id == inv.id)).all()
    return {"nodes": [{"id": e.id, "type": e.entity_type, "label": e.value} for e in entities],
            "edges": [{"id": r.id, "source": r.source_entity_id, "target": r.target_entity_id, "label": r.relationship_type, "confidence": r.confidence} for r in relations]}

@router.get("/investigations/{investigation_id}/credentials", dependencies=[Depends(require_auth)])
def list_credentials(investigation_id: str, db: Session = Depends(get_db)):
    if not db.get(Investigation, investigation_id):
        raise HTTPException(404, "Investigation not found")
    rows = db.scalars(select(CredentialRecord).where(CredentialRecord.investigation_id == investigation_id).order_by(CredentialRecord.created_at.desc())).all()
    return [{"id": x.id, "identifier_type": x.identifier_type, "identifier_reference": x.identifier_reference, "created_at": x.created_at.isoformat(), "last_accessed_at": x.last_accessed_at.isoformat() if x.last_accessed_at else None, "password_state": "stored_encrypted_hidden"} for x in rows]

@router.post("/investigations/{investigation_id}/credentials", dependencies=[Depends(require_auth)])
def create_credential(investigation_id: str, payload: CredentialIn, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv: raise HTTPException(404, "Investigation not found")
    target = db.get(Target, payload.target_id) if payload.target_id else None
    if payload.target_id and (not target or target.investigation_id != inv.id): raise HTTPException(400, "Target does not belong to this investigation")
    row = CredentialRecord(investigation_id=inv.id, target_id=target.id if target else None,
                           identifier_type=payload.identifier_type, identifier_reference=payload.identifier_reference,
                           encrypted_password=encrypt_secret(payload.password), authorization_context=payload.authorization_context)
    db.add(row); db.flush(); audit(db, "credential.created", "credential", row.id, inv.id, "Encrypted credential record created; secret not logged")
    db.commit(); db.refresh(row)
    return {"id": row.id, "identifier_type": row.identifier_type, "identifier_reference": row.identifier_reference, "password_state": "stored_encrypted_hidden", "warning": "AUTHORIZED USE ONLY — Passwords are confidential. View only with explicit authorization."}

@router.post("/credentials/{credential_id}/reveal", dependencies=[Depends(require_auth)])
def reveal_credential(credential_id: str, response: Response, db: Session = Depends(get_db)):
    row = db.get(CredentialRecord, credential_id)
    if not row: raise HTTPException(404, "Credential record not found")
    try:
        plaintext = decrypt_secret(row.encrypted_password)
    except ValueError as exc:
        raise HTTPException(500, str(exc)) from exc
    row.last_accessed_at = now_utc()
    audit(db, "credential.revealed", "credential", row.id, row.investigation_id, "Password revealed through authorized UI action")
    db.commit()
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return {"password": plaintext, "warning": "AUTHORIZED USE ONLY — Passwords are confidential. View and handle only with explicit authorization."}

@router.post("/investigations/{investigation_id}/uploads", dependencies=[Depends(require_auth)])
async def upload_file(investigation_id: str, file: UploadFile = File(...), target_id: str | None = Form(default=None), db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv: raise HTTPException(404, "Investigation not found")
    target = db.get(Target, target_id) if target_id else None
    if target_id and (not target or target.investigation_id != inv.id): raise HTTPException(400, "Target does not belong to this investigation")
    safe_name = Path(file.filename or "upload.bin").name.replace("..", "_")[:180]
    suffix = Path(safe_name).suffix.lower()
    allowed = {".jpg", ".jpeg", ".png", ".tiff", ".webp", ".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".md", ".csv", ".json", ".xml", ".log", ".bin"}
    if suffix not in allowed: raise HTTPException(415, "Unsupported file type")
    raw = await file.read(settings.max_upload_mb * 1024 * 1024 + 1)
    if len(raw) > settings.max_upload_mb * 1024 * 1024: raise HTTPException(413, f"Maximum upload size is {settings.max_upload_mb} MB")
    file_id = str(uuid.uuid4())
    path = STORAGE_DIR / "uploads" / f"{file_id}{suffix}"
    path.write_bytes(raw)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    try:
        digest = sha256_file(path)
        metadata = extract_file_metadata(path, safe_name)
    except Exception as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(422, f"File parsing failed: {str(exc)[:250]}") from exc
    evidence = Evidence(investigation_id=inv.id, target_id=target.id if target else None, evidence_type="uploaded_file", sha256=digest,
                        content_excerpt=json.dumps(metadata, ensure_ascii=False)[:5000], storage_path=str(path.relative_to(STORAGE_DIR.parent)))
    db.add(evidence); db.flush()
    finding = Finding(investigation_id=inv.id, target_id=target.id if target else None, module="image" if suffix in {".jpg", ".jpeg", ".png", ".tiff", ".webp"} else "document",
                      finding_type="uploaded_file_metadata", value=safe_name, details=metadata, confidence=1.0, verification_status="observed", evidence_id=evidence.id)
    db.add(finding); audit(db, "file.uploaded", "evidence", evidence.id, inv.id, f"filename={safe_name}; sha256={digest}"); db.commit()
    return {"evidence_id": evidence.id, "finding_id": finding.id, "filename": safe_name, "sha256": digest, "metadata": metadata}

@router.get("/investigations/{investigation_id}/report", dependencies=[Depends(require_auth)])
def get_report(investigation_id: str, format: str = "json", db: Session = Depends(get_db)):
    try: payload = investigation_payload(db, investigation_id)
    except ValueError as exc: raise HTTPException(404, str(exc)) from exc
    if format == "json": return payload
    if format == "html": return Response(render_html(payload), media_type="text/html; charset=utf-8")
    if format == "pdf": return Response(render_pdf(payload), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="cyber-x-{investigation_id}.pdf"'})
    raise HTTPException(400, "Supported formats: json, html, pdf")

@router.get("/sources", dependencies=[Depends(require_auth)])
def list_sources(db: Session = Depends(get_db)):
    rows = db.scalars(select(Source).order_by(Source.category, Source.name)).all()
    return [{"id": s.id, "name": s.name, "category": s.category, "source_url": s.source_url, "status": s.status, "description": s.description, "last_checked_at": s.last_checked_at.isoformat() if s.last_checked_at else None} for s in rows]

@router.post("/sources", dependencies=[Depends(require_auth)])
def add_source(payload: SourceIn, db: Session = Depends(get_db)):
    existing = db.scalar(select(Source).where(Source.name == payload.name))
    if existing: raise HTTPException(409, "A source with this name already exists")
    source_url = payload.source_url
    if source_url:
        try:
            source_url = normalize_http_url(source_url)
        except ValueError as exc:
            raise HTTPException(400, "Source URL must be a valid HTTP(S) URL without embedded credentials") from exc
    row = Source(name=payload.name, category=payload.category, source_url=source_url, description=payload.description)
    db.add(row); db.flush(); audit(db, "source.created", "source", row.id, detail="Public source configuration added"); db.commit(); db.refresh(row)
    return {"id": row.id, "name": row.name, "category": row.category, "status": row.status}


@router.delete("/credentials/{credential_id}", dependencies=[Depends(require_auth)])
def delete_credential(credential_id: str, db: Session = Depends(get_db)):
    row = db.get(CredentialRecord, credential_id)
    if not row: raise HTTPException(404, "Credential record not found")
    audit(db, "credential.deleted", "credential", row.id, row.investigation_id, "Encrypted credential record deleted")
    db.delete(row); db.commit()
    return {"deleted": True}

@router.get("/investigations/{investigation_id}/evidence", dependencies=[Depends(require_auth)])
def list_evidence(investigation_id: str, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv: raise HTTPException(404, "Investigation not found")
    rows = db.scalars(select(Evidence).where(Evidence.investigation_id == inv.id).order_by(Evidence.collected_at.desc())).all()
    return [{"id": e.id, "target_id": e.target_id, "source_url": e.source_url, "evidence_type": e.evidence_type, "sha256": e.sha256, "collected_at": e.collected_at.isoformat(), "content_excerpt": e.content_excerpt, "collector_version": e.collector_version} for e in rows]

@router.get("/investigations/{investigation_id}/timeline", dependencies=[Depends(require_auth)])
def get_timeline(investigation_id: str, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv: raise HTTPException(404, "Investigation not found")
    rows = db.scalars(select(Finding).where(Finding.investigation_id == inv.id).order_by(Finding.collected_at.asc())).all()
    return [{"id": f.id, "timestamp": f.collected_at.isoformat(), "module": f.module, "event": f.finding_type, "summary": f.value[:350], "source_url": f.source_url, "confidence": f.confidence, "evidence_id": f.evidence_id} for f in rows]

@router.post("/investigations/{investigation_id}/targets/{target_id}/breach-check", dependencies=[Depends(require_auth)])
async def authorized_breach_check(investigation_id: str, target_id: str, payload: BreachCheckIn, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    target = db.get(Target, target_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    if not target or target.investigation_id != inv.id:
        raise HTTPException(404, "Target not found in this investigation")
    if target.target_type != "email":
        raise HTTPException(400, "Public incident reference search currently requires an email target")
    try:
        references = await lookup_email_breaches(target.normalized_value)
    except Exception as exc:
        raise HTTPException(502, f"Public HTML search failed: {str(exc)[:180]}") from exc

    summary = f"Found {len(references)} public incident reference(s)" if references else "No indexed public incident references returned"
    details = {
        "collection_mode": "public_html_scraping",
        "source": "DuckDuckGo public HTML results",
        "reference_count": len(references),
        "references": references,
        "authorization_context_supplied": True,
        "credential_material_collected": False,
        "interpretation": "Search references are leads for analyst verification, not proof of account compromise or inclusion in a breach.",
    }
    evidence_payload = json.dumps(details, sort_keys=True, ensure_ascii=False)
    evidence = Evidence(investigation_id=inv.id, target_id=target.id, evidence_type="public_incident_references",
                        sha256=hashlib.sha256(evidence_payload.encode("utf-8")).hexdigest(),
                        content_excerpt=evidence_payload[:5000], collector_version="1.5.0")
    db.add(evidence); db.flush()
    finding = Finding(investigation_id=inv.id, target_id=target.id, module="breach", finding_type="public_breach_references",
                      value=summary, details=details,
                      source_url="https://html.duckduckgo.com/html/" if references else None,
                      confidence=0.65 if references else 0.35, verification_status="observed" if references else "unverified",
                      evidence_id=evidence.id)
    db.add(finding)
    audit(db, "breach.public_html_search", "finding", finding.id, inv.id,
          f"mode=public_html_scraping; references={len(references)}; authorization_context_supplied=true; credential_material=false")
    db.commit()
    return {"finding_id": finding.id, "breach_count": len(references), "reference_count": len(references),
            "references": references, "message": summary, "credential_material_collected": False,
            "interpretation": details["interpretation"]}


@router.post("/investigations/{investigation_id}/password-exposure-check", dependencies=[Depends(require_auth)])
async def password_exposure_check(investigation_id: str, payload: PasswordExposureIn, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    target = db.get(Target, payload.target_id) if payload.target_id else None
    if payload.target_id and (not target or target.investigation_id != inv.id):
        raise HTTPException(400, "Target does not belong to this investigation")
    try:
        result = await check_password_exposure(payload.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    is_common = bool(result.get("is_common", result.get("is_exposed", False)))
    details = {**result, "is_common": is_common, "is_exposed": is_common, "credential_material_collected": False, "authorization_context_supplied": True}
    value = "Matches local common-password checks" if is_common else "No match in the local common-password checks"
    evidence_payload = json.dumps(details, sort_keys=True, ensure_ascii=False)
    evidence = Evidence(investigation_id=inv.id, target_id=target.id if target else None,
                        evidence_type="local_password_hygiene_result",
                        sha256=hashlib.sha256(evidence_payload.encode("utf-8")).hexdigest(),
                        content_excerpt=evidence_payload[:2000], collector_version="1.5.0")
    db.add(evidence); db.flush()
    finding = Finding(investigation_id=inv.id, target_id=target.id if target else None, module="credential",
                      finding_type="password_exposure_check", value=value, details=details,
                      confidence=0.8 if is_common else 0.45,
                      verification_status="observed", evidence_id=evidence.id)
    db.add(finding)
    audit(db, "credential.local_hygiene_checked", "finding", finding.id, inv.id,
          f"method=local_weak_password_heuristics; common={is_common}; candidate_not_stored=true; no_external_request=true")
    db.commit()
    return {"finding_id": finding.id, **result, "candidate_stored": False}


@router.get("/authorized-databases", dependencies=[Depends(require_auth)])
def list_authorized_databases():
    try:
        return public_database_catalog()
    except AuthorizedDatabaseError as exc:
        raise HTTPException(500, str(exc)) from exc


@router.post("/investigations/{investigation_id}/database-lookups", dependencies=[Depends(require_auth)])
def authorized_database_lookup(investigation_id: str, payload: DatabaseLookupIn, db: Session = Depends(get_db)):
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    target = db.get(Target, payload.target_id)
    if not target or target.investigation_id != inv.id:
        raise HTTPException(400, "Target does not belong to this investigation")
    try:
        count = count_exact_matches(payload.connector_name, payload.table, payload.column, target.normalized_value)
    except AuthorizedDatabaseError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"Authorized database query failed: {type(exc).__name__}") from exc

    details = {"connector": payload.connector_name, "table": payload.table, "column": payload.column,
               "match_count": count, "query_mode": "exact_parameterized_read_only_count",
               "authorization_context_supplied": True, "row_data_returned": False}
    summary = f"{count} exact match(es) in authorized database connector"
    evidence_payload = json.dumps(details, sort_keys=True, ensure_ascii=False)
    evidence = Evidence(investigation_id=inv.id, target_id=target.id, evidence_type="authorized_database_lookup",
                        sha256=hashlib.sha256(evidence_payload.encode("utf-8")).hexdigest(),
                        content_excerpt=evidence_payload, collector_version="1.5.0")
    db.add(evidence); db.flush()
    finding = Finding(investigation_id=inv.id, target_id=target.id, module="credential",
                      finding_type="authorized_database_match_count", value=summary, details=details,
                      confidence=1.0, verification_status="observed", evidence_id=evidence.id)
    db.add(finding)
    audit(db, "database.authorized_lookup", "finding", finding.id, inv.id,
          f"connector={payload.connector_name}; table={payload.table}; column={payload.column}; matches={count}; rows_returned=false")
    db.commit()
    return {"finding_id": finding.id, **details, "message": summary}


@router.get("/audit", dependencies=[Depends(require_auth)])
def list_audit(limit: int = 100, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    rows = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)).all()
    return [{"id": x.id, "action": x.action, "object_type": x.object_type, "object_id": x.object_id, "detail": x.detail, "created_at": x.created_at.isoformat()} for x in rows]


class ExposureCheckIn(BaseModel):
    target_id: str
    authorization_context: str = Field(min_length=12, max_length=1000)


@router.get("/exposure-datasets", dependencies=[Depends(require_auth)])
def list_exposure_datasets(db: Session = Depends(get_db)):
    rows = db.scalars(select(ExposureDataset).order_by(ExposureDataset.created_at.desc())).all()
    return [{"id": row.id, "name": row.name, "source_label": row.source_label,
             "description": row.description, "source_reference": row.source_reference,
             "row_count": row.row_count, "sha256": row.sha256,
             "created_at": row.created_at.isoformat()} for row in rows]


@router.post("/exposure-datasets", dependencies=[Depends(require_auth)])
async def import_exposure_dataset(
    name: str = Form(..., min_length=2, max_length=180),
    source_label: str = Form(..., min_length=2, max_length=180),
    description: str = Form(default="", max_length=1000),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    filename = Path(file.filename or "").name
    if len(settings.exposure_hmac_key.strip()) < 32:
        raise HTTPException(503, "Configure EXPOSURE_HMAC_KEY with at least 32 characters before using Exposure Lab")
    if Path(filename).suffix.casefold() != ".csv":
        raise HTTPException(415, "Exposure index imports must be CSV files")
    raw = await file.read(MAX_DATASET_BYTES + 1)
    try:
        records, digest = parse_redacted_csv(raw)
    except DatasetValidationError as exc:
        raise HTTPException(400, str(exc)) from exc
    duplicate = db.scalar(select(ExposureDataset).where(ExposureDataset.sha256 == digest))
    if duplicate:
        raise HTTPException(409, "This exact dataset has already been imported")

    dataset = ExposureDataset(
        name=name.strip(), source_label=source_label.strip(),
        description=description.strip() or None, row_count=len(records), sha256=digest,
    )
    db.add(dataset)
    db.flush()
    inserted = 0
    seen = set()
    for record in records:
        for indicator in record["indicators"]:
            dedupe_key = (indicator["type"], indicator["hmac"], record["breach_name"], record["breach_date"])
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            db.add(ExposureIndicator(
                dataset_id=dataset.id, indicator_type=indicator["type"],
                identifier_hmac=indicator["hmac"], masked_identifier=indicator["masked"],
                breach_name=record["breach_name"], breach_date=record["breach_date"],
                source_reference=record["source_reference"],
            ))
            inserted += 1
    dataset.row_count = len(records)
    audit(db, "exposure.dataset_imported", "exposure_dataset", dataset.id,
          detail=f"source={source_label.strip()[:120]}; rows={len(records)}; indicators={inserted}; sha256={digest}; raw_secrets=false")
    db.commit()
    return {"id": dataset.id, "name": dataset.name, "row_count": dataset.row_count,
            "indicator_count": inserted, "sha256": digest,
            "storage_mode": "keyed-HMAC identifiers only; source CSV bytes discarded"}


@router.delete("/exposure-datasets/{dataset_id}", dependencies=[Depends(require_auth)])
def delete_exposure_dataset(dataset_id: str, db: Session = Depends(get_db)):
    row = db.get(ExposureDataset, dataset_id)
    if not row:
        raise HTTPException(404, "Exposure dataset not found")
    db.query(ExposureIndicator).filter(ExposureIndicator.dataset_id == row.id).delete(synchronize_session=False)
    audit(db, "exposure.dataset_deleted", "exposure_dataset", row.id,
          detail=f"name={row.name[:120]}; indexed_indicators_deleted=true")
    db.delete(row)
    db.commit()
    return {"deleted": True}


@router.post("/investigations/{investigation_id}/exposure-check", dependencies=[Depends(require_auth)])
def check_target_against_exposure_indexes(
    investigation_id: str, payload: ExposureCheckIn, db: Session = Depends(get_db)
):
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    target = db.get(Target, payload.target_id)
    if not target or target.investigation_id != inv.id:
        raise HTTPException(404, "Target not found in this investigation")
    if target.target_type not in {"email", "username", "domain"}:
        raise HTTPException(400, "Exposure-index matching supports email, username and domain targets")
    try:
        digest = identifier_hmac(target.target_type, target.normalized_value)
    except DatasetValidationError as exc:
        raise HTTPException(503, str(exc)) from exc

    matches = db.execute(
        select(ExposureIndicator, ExposureDataset)
        .join(ExposureDataset, ExposureDataset.id == ExposureIndicator.dataset_id)
        .where(ExposureIndicator.indicator_type == target.target_type,
               ExposureIndicator.identifier_hmac == digest)
        .order_by(ExposureDataset.created_at.desc())
        .limit(100)
    ).all()
    references = [{
        "dataset": dataset.name, "source_label": dataset.source_label,
        "masked_identifier": indicator.masked_identifier,
        "breach_name": indicator.breach_name, "breach_date": indicator.breach_date,
        "source_reference": indicator.source_reference,
    } for indicator, dataset in matches]
    details = {
        "match_count": len(references), "matches": references,
        "match_method": "HMAC-SHA256 exact identifier match against analyst-imported redacted indexes",
        "raw_identifier_stored_in_index": False, "passwords_or_tokens_collected": False,
        "authorization_context_supplied": True,
        "interpretation": "A match means the identifier is present in an analyst-imported index. Confirm provenance and incident context before treating it as a verified breach."
    }
    summary = (f"Identifier matched {len(references)} exposure index record(s)" if references
               else "No exact match in the currently imported exposure indexes")
    evidence_raw = json.dumps(details, sort_keys=True, ensure_ascii=False)
    evidence = Evidence(
        investigation_id=inv.id, target_id=target.id, evidence_type="redacted_exposure_index_match",
        sha256=hashlib.sha256(evidence_raw.encode("utf-8")).hexdigest(),
        content_excerpt=evidence_raw[:5000], collector_version="1.5.0",
    )
    db.add(evidence)
    db.flush()
    finding = Finding(
        investigation_id=inv.id, target_id=target.id, module="breach",
        finding_type="redacted_exposure_index_match", value=summary, details=details,
        confidence=1.0 if references else 0.4, verification_status="observed" if references else "unverified",
        evidence_id=evidence.id,
    )
    db.add(finding)
    audit(db, "exposure.identifier_checked", "finding", finding.id, inv.id,
          f"target_type={target.target_type}; matches={len(references)}; keyed_hmac=true; raw_secrets=false")
    db.commit()
    return {"finding_id": finding.id, "match_count": len(references), "matches": references,
            "message": summary, "interpretation": details["interpretation"],
            "raw_identifier_stored_in_index": False}


@router.get("/exposure-datasets/template.csv", dependencies=[Depends(require_auth)])
def exposure_dataset_template():
    content = (
        "email,username,domain,breach_name,breach_date,source_reference\n"
        "analyst@example.test,analyst,example.test,Synthetic University Exercise,2026-01-15,https://example.test/report\n"
    )
    return Response(content=content, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=cyber-x-exposure-index-template.csv"})
