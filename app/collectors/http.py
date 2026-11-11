import httpx
from urllib.parse import urljoin, urlsplit
from app.core.config import settings
from .safety import normalize_http_url, validate_public_host, UnsafeTarget

async def safe_get(url: str, *, accept: str = "*/*", max_bytes: int = 2_000_000, allowed_hosts: set[str] | None = None) -> tuple[httpx.Response, str]:
    current = normalize_http_url(url)
    headers = {"User-Agent": settings.user_agent, "Accept": accept}
    timeout = httpx.Timeout(settings.request_timeout_seconds)
    async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=False, verify=True, trust_env=False) as client:
        for _ in range(4):
            parsed = urlsplit(current)
            host = parsed.hostname or ""
            if allowed_hosts is not None and host not in allowed_hosts:
                raise UnsafeTarget("Redirect left the permitted source host")
            validate_public_host(host)
            async with client.stream("GET", current) as response:
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        raise UnsafeTarget("Redirect did not contain a Location header")
                    current = normalize_http_url(urljoin(current, location))
                    continue
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        raise ValueError(f"Response exceeded {max_bytes} bytes")
                final = httpx.Response(response.status_code, headers=response.headers, content=bytes(body), request=response.request)
                return final, current
    raise UnsafeTarget("Too many redirects")
