"""Stateless, public-source OSINT API.

Scan results exist only in the request/response memory. Nothing is written to a
database, local file, investigation history, or evidence store.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.targets import detect_target, modules_for_target
from app.collectors.collectors import collect_module

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")

SUPPORTED_MODULES = {
    "username", "email", "phone", "domain", "ip", "social", "website",
    "breach", "threat", "search", "github", "network", "attack_surface",
    "digital_footprint", "correlation",
}
MODULE_LABELS = {
    "username": "Username Intelligence", "email": "Email Intelligence",
    "phone": "Phone Intelligence", "domain": "Domain Intelligence",
    "ip": "IP Intelligence", "social": "Social Media Intelligence",
    "website": "Website Intelligence", "breach": "Public Incident References",
    "threat": "Threat Intelligence", "search": "Search Engine Intelligence",
    "github": "GitHub & Code Intelligence", "network": "Network Intelligence",
    "attack_surface": "Passive Attack Surface", "digital_footprint": "Digital Footprint",
    "correlation": "Entity Correlation",
}


class ScanIn(BaseModel):
    target: str = Field(min_length=2, max_length=2048)
    modules: list[str] | None = Field(default=None, max_length=8)


async def require_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None),
) -> None:
    token = x_api_token
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:]
    if settings.api_token:
        expected = settings.api_token
        valid = bool(expected and token and hmac.compare_digest(hashlib.sha256(token.encode()).digest(), hashlib.sha256(expected.encode()).digest()))
        if not valid:
            raise HTTPException(status_code=401, detail="Missing or invalid workspace access token")
        return
    if request.headers.get("x-vercel-id") or settings.app_env.lower() == "production":
        raise HTTPException(
            status_code=503,
            detail="Remote workspace is locked. Set API_TOKEN in the deployment environment.",
        )
    # Local development is allowed only from loopback.
    import ipaddress
    host = request.client.host if request.client else ""
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise HTTPException(status_code=401, detail="Remote access requires API_TOKEN")


@router.get("/modules", dependencies=[Depends(require_auth)])
def list_modules() -> list[dict[str, str]]:
    return [{"id": key, "name": value} for key, value in MODULE_LABELS.items()]


@router.post("/scan", dependencies=[Depends(require_auth)])
async def scan(payload: ScanIn) -> dict[str, Any]:
    try:
        target_type, normalized = detect_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    recommended = [m for m in modules_for_target(target_type) if m in SUPPORTED_MODULES]
    requested = payload.modules if payload.modules is not None else recommended
    # Do not allow arbitrary module names or manual credential/file workflows.
    selected = list(dict.fromkeys(m for m in requested if m in SUPPORTED_MODULES))
    if not selected:
        raise HTTPException(status_code=400, detail="Select at least one supported public-source module")
    if len(selected) > 8:
        raise HTTPException(status_code=400, detail="A scan is limited to 8 modules")

    semaphore = asyncio.Semaphore(3)

    async def run_one(module: str) -> dict[str, Any]:
        async with semaphore:
            try:
                findings = await asyncio.wait_for(
                    collect_module(module, normalized, target_type),
                    timeout=max(5.0, min(settings.request_timeout_seconds * 3, 30.0)),
                )
                safe_findings = []
                for item in findings[:100]:
                    safe_findings.append({
                        "module": str(item.get("module", module))[:80],
                        "finding_type": str(item.get("finding_type", "observation"))[:100],
                        "value": str(item.get("value", ""))[:5000],
                        "details": item.get("details") if isinstance(item.get("details"), (dict, list, str, int, float, bool, type(None))) else {},
                        "source_url": item.get("source_url"),
                        "confidence": max(0.0, min(1.0, float(item.get("confidence", 0.5)))),
                        "verification_status": str(item.get("verification_status", "unverified"))[:40],
                    })
                return {"module": module, "label": MODULE_LABELS[module], "status": "completed", "findings": safe_findings}
            except asyncio.TimeoutError:
                return {"module": module, "label": MODULE_LABELS[module], "status": "timeout", "findings": [],
                        "error": "The source did not respond within the collection time limit."}
            except Exception as exc:
                log.warning("Public collector %s failed: %s", module, type(exc).__name__)
                return {"module": module, "label": MODULE_LABELS[module], "status": "unavailable", "findings": [],
                        "error": f"Source unavailable ({type(exc).__name__})."}

    module_results = await asyncio.gather(*(run_one(module) for module in selected))
    findings = [finding for result in module_results for finding in result["findings"]]
    return {
        "target": payload.target.strip(),
        "normalized_target": normalized,
        "target_type": target_type,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "storage": "memory_only",
        "modules": module_results,
        "findings": findings,
        "summary": {
            "modules_requested": len(selected),
            "modules_completed": sum(result["status"] == "completed" for result in module_results),
            "modules_unavailable": sum(result["status"] != "completed" for result in module_results),
            "findings": len(findings),
        },
        "limitations": [
            "Only publicly accessible sources are queried.",
            "A missing result does not prove that information does not exist.",
            "Public incident references do not prove that an account or password was compromised.",
            "No passwords, private dumps, login-gated pages, or access-controlled records are collected.",
            "Results are transient and are not stored by this application.",
        ],
    }
