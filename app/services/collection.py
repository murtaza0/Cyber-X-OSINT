import asyncio
import hashlib
import json
import logging
from app.db.database import SessionLocal
from app.models.models import CollectionJob, Target, Finding, Evidence, now_utc
from app.collectors.collectors import collect_module
from .correlation import correlate_finding

log = logging.getLogger(__name__)

def run_collection_job(job_id: str):
    db = SessionLocal()
    try:
        job = db.get(CollectionJob, job_id)
        if not job:
            return
        target = db.get(Target, job.target_id)
        if not target:
            job.status = "failed"; job.error = "Target record not found"; job.finished_at = now_utc(); db.commit(); return
        job.status = "running"; job.started_at = now_utc(); db.commit()
        total = 0
        module_errors = []
        successful_modules = 0
        try:
            for module in job.modules:
                try:
                    collected = asyncio.run(collect_module(module, target.normalized_value, target.target_type))
                    successful_modules += 1
                    for item in collected:
                        # Store a digest of the observed finding data as an evidence record.
                        evidence_payload = json.dumps({"value": item.get("value"), "details": item.get("details", {}), "source": item.get("source_url")}, sort_keys=True, ensure_ascii=False)
                        digest = hashlib.sha256(evidence_payload.encode("utf-8")).hexdigest()
                        evidence = Evidence(investigation_id=job.investigation_id, target_id=target.id,
                                            source_url=item.get("source_url"), evidence_type="web_observation" if item.get("source_url") else "derived_observation",
                                            sha256=digest, content_excerpt=evidence_payload[:2000], collector_version="1.5.0")
                        db.add(evidence); db.flush()
                        finding = Finding(investigation_id=job.investigation_id, target_id=target.id, job_id=job.id,
                                          module=item.get("module", module), finding_type=item.get("finding_type", "observation"),
                                          value=str(item.get("value", "")), details=item.get("details", {}),
                                          source_url=item.get("source_url"), confidence=float(item.get("confidence", 0.5)),
                                          verification_status=item.get("verification_status", "unverified"), evidence_id=evidence.id)
                        db.add(finding); db.flush()
                        correlate_finding(db, finding, target)
                        total += 1
                    db.commit()
                except Exception as exc:
                    log.warning("Collector module %s failed for job %s: %s", module, job_id, exc)
                    module_errors.append(module)
                    db.rollback()
                    # Keep a visible error finding without fabricating source data.
                    error_evidence = Evidence(investigation_id=job.investigation_id, target_id=target.id,
                                              evidence_type="collector_error", sha256=hashlib.sha256(str(exc).encode()).hexdigest(),
                                              content_excerpt=f"{module}: {str(exc)[:400]}", collector_version="1.5.0")
                    db.add(error_evidence); db.flush()
                    db.add(Finding(investigation_id=job.investigation_id, target_id=target.id, job_id=job.id,
                                   module=module, finding_type="collector_error", value=str(exc)[:400],
                                   details={"module": module}, confidence=0.1, verification_status="source_error",
                                   evidence_id=error_evidence.id))
                    total += 1
                    db.commit()
            job = db.get(CollectionJob, job_id)
            job.status = "partial" if module_errors and successful_modules else ("failed" if module_errors else "completed")
            job.findings_count = total
            job.error = ("Failed modules: " + ", ".join(module_errors))[:1000] if module_errors else None
            job.finished_at = now_utc()
            db.commit()
        except Exception as exc:
            db.rollback()
            job = db.get(CollectionJob, job_id)
            if job:
                job.status = "failed"; job.error = str(exc)[:1000]; job.finished_at = now_utc(); db.commit()
    finally:
        db.close()
