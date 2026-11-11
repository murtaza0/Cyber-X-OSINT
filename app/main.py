import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings, ROOT_DIR
from app.api.stateless_routes import router


logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # No database, migrations, local data files, or startup seeding.
    yield


app = FastAPI(
    title=settings.app_name,
    version="2.0.0",
    description="Stateless OSINT workspace for permitted public-source research.",
    lifespan=lifespan,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
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
        response.headers.setdefault("Cache-Control", "no-store")
        return response


app.add_middleware(SecurityHeadersMiddleware)
app.include_router(router)
app.mount("/static", StaticFiles(directory=str(ROOT_DIR / "static")), name="static")


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, exc: RequestValidationError):
    safe_errors = []
    for error in exc.errors():
        loc = ".".join(str(part) for part in error.get("loc", ()))
        safe_errors.append({"field": loc, "message": error.get("msg", "Invalid value")})
    return JSONResponse(status_code=422, content={"detail": "Request validation failed", "errors": safe_errors})


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(ROOT_DIR / "static" / "index.html")


@app.get("/health")
async def health():
    return {"status": "ok", "service": settings.app_name, "version": "2.0.0", "storage": "memory_only"}
