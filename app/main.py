import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import select
from app.core.config import settings, ROOT_DIR, IS_VERCEL
from app.db.database import Base, engine, SessionLocal, DATABASE_URL
from app.models.models import Source
from app.api.routes import router

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(name)s %(message)s")

DEFAULT_SOURCES = [
    ("crt.sh Public HTML", "domain", "https://crt.sh/", "Certificate transparency result pages parsed as HTML; no JSON endpoint."),
    ("GitHub Public Profiles", "code", "https://github.com/", "Public profile and repository pages parsed from HTML; no GitHub API."),
    ("DuckDuckGo HTML Search", "search", "https://html.duckduckgo.com/html/", "Public search-result HTML parsed locally; no search API."),
    ("URLhaus Public Pages", "threat", "https://urlhaus.abuse.ch/browse/", "Public threat-intelligence pages; no API endpoint."),
    ("Hurricane Electric BGP Toolkit", "network", "https://bgp.he.net/", "Public routing and ASN reference pages parsed as HTML."),
]

@asynccontextmanager
async def lifespan(app: FastAPI):
    if IS_VERCEL and DATABASE_URL.startswith("sqlite"):
        raise RuntimeError("Vercel deployment requires a persistent PostgreSQL DATABASE_URL; temporary SQLite is disabled to prevent silent data loss")
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        for name, category, url, desc in DEFAULT_SOURCES:
            if not db.scalar(select(Source).where(Source.name == name)):
                db.add(Source(name=name, category=category, source_url=url, description=desc, status="configured"))
        db.commit()
    finally:
        db.close()
    yield

app = FastAPI(title=settings.app_name, version="1.5.0", description="Self-hosted OSINT platform with public collectors and owner-authorized exposure intelligence", lifespan=lifespan)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.include_router(router)

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc: RequestValidationError):
    # Do not echo request bodies: validation errors can otherwise include sensitive password input.
    safe_errors = []
    for error in exc.errors():
        loc = ".".join(str(part) for part in error.get("loc", ()))
        safe_errors.append({"field": loc, "message": error.get("msg", "Invalid value")})
    return JSONResponse(status_code=422, content={"detail": "Request validation failed", "errors": safe_errors})
app.mount("/static", StaticFiles(directory=str(ROOT_DIR / "static")), name="static")

@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(ROOT_DIR / "static" / "index.html")

@app.get("/health")
async def health():
    return {"status": "ok", "service": settings.app_name, "version": "1.5.0"}
