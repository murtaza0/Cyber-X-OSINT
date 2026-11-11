import ipaddress
import re
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.models import Entity, Relationship, Target, Finding

EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
DOMAIN_RE = re.compile(r"(?<![@\w-])(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,63}(?![\w-])")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")

def get_or_create_entity(db: Session, investigation_id: str, entity_type: str, value: str) -> Entity | None:
    value = value.strip().strip(".,;()[]{}<>")
    if len(value) < 3 or len(value) > 2048:
        return None
    normalized = value.lower()
    existing = db.scalar(select(Entity).where(Entity.investigation_id == investigation_id, Entity.entity_type == entity_type, Entity.normalized_value == normalized))
    if existing:
        return existing
    entity = Entity(investigation_id=investigation_id, entity_type=entity_type, value=value, normalized_value=normalized)
    db.add(entity); db.flush()
    return entity

def _extract_entities(text: str):
    for item in EMAIL_RE.findall(text or ""):
        yield "email", item
    for item in IP_RE.findall(text or ""):
        try:
            ipaddress.ip_address(item)
            yield "ip", item
        except ValueError:
            pass
    for item in IPV6_RE.findall(text or ""):
        try:
            yield "ip", str(ipaddress.ip_address(item))
        except ValueError:
            continue
    for item in DOMAIN_RE.findall(text or ""):
        yield "domain", item

def correlate_finding(db: Session, finding: Finding, target: Target):
    seed = get_or_create_entity(db, target.investigation_id, target.target_type, target.normalized_value)
    if not seed:
        return
    candidate_text = " ".join([finding.value or "", str(finding.details or "")])
    seen = set()
    for entity_type, value in _extract_entities(candidate_text):
        key = (entity_type, value.lower())
        if key in seen or value.lower() == target.normalized_value.lower():
            continue
        seen.add(key)
        entity = get_or_create_entity(db, target.investigation_id, entity_type, value)
        if not entity:
            continue
        exists = db.scalar(select(Relationship).where(
            Relationship.investigation_id == target.investigation_id,
            Relationship.source_entity_id == seed.id,
            Relationship.target_entity_id == entity.id,
            Relationship.relationship_type == "observed_in_finding",
        ))
        if not exists:
            db.add(Relationship(investigation_id=target.investigation_id, source_entity_id=seed.id,
                                target_entity_id=entity.id, relationship_type="observed_in_finding",
                                confidence=min(max(finding.confidence, 0.1), 1.0), evidence_id=finding.evidence_id))
