"""HTML-only public web collection helpers. No provider JSON/API endpoints are used."""
from __future__ import annotations

from urllib.parse import parse_qs, quote, urlsplit
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from app.core.config import settings
from .http import safe_get
from .safety import normalize_http_url

SEARCH_HOST = "html.duckduckgo.com"


async def public_page(url: str, *, max_bytes: int = 1_500_000, obey_robots: bool = True):
    normalized = normalize_http_url(url)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    if obey_robots:
        robots, _ = await safe_get(
            robots_url,
            accept="text/plain,*/*",
            max_bytes=128_000,
            allowed_hosts={host},
        )
        if robots.status_code in {401, 403} or robots.status_code >= 500:
            raise PermissionError(f"Source robots policy unavailable (HTTP {robots.status_code}); fetch skipped")
        if robots.status_code == 200:
            rules = RobotFileParser()
            rules.parse(robots.text.splitlines())
            if not rules.can_fetch(settings.user_agent, normalized):
                raise PermissionError("Source robots.txt disallows this public page; fetch skipped")
    response, final = await safe_get(
        normalized,
        accept="text/html,application/xhtml+xml;q=0.9,text/plain;q=0.5",
        max_bytes=max_bytes,
        allowed_hosts={host},
    )
    if response.status_code in {401, 403, 407}:
        raise PermissionError(f"Source requires authentication or denies automated access (HTTP {response.status_code})")
    if response.status_code == 429:
        raise PermissionError("Source rate-limited automated access (HTTP 429); retry later")
    return response, final


def _unwrap_result_url(raw: str) -> str | None:
    raw = (raw or "").strip()
    if raw.startswith("//"):
        raw = "https:" + raw
    parsed = urlsplit(raw)
    if parsed.hostname in {SEARCH_HOST, "duckduckgo.com"}:
        params = parse_qs(parsed.query)
        raw = (params.get("uddg") or [""])[0]
    candidate = urlsplit(raw)
    if candidate.scheme not in {"http", "https"} or not candidate.hostname:
        return None
    if candidate.username or candidate.password:
        return None
    return raw


async def search_public_html(query: str, *, limit: int = 8) -> list[dict]:
    """Scrape ordinary public HTML search results; no search API or login session."""
    if not query.strip():
        return []
    url = f"https://{SEARCH_HOST}/html/?q={quote(query[:400], safe='')}"
    response, final = await public_page(url, max_bytes=2_000_000, obey_robots=True)
    if response.status_code != 200:
        raise RuntimeError(f"Public HTML search returned HTTP {response.status_code}")
    soup = BeautifulSoup(response.text, "lxml")
    results: list[dict] = []
    for card in soup.select(".result")[: max(1, min(limit, 12))]:
        anchor = card.select_one("a.result__a")
        if not anchor:
            continue
        result_url = _unwrap_result_url(anchor.get("href", ""))
        if not result_url:
            continue
        snippet_node = card.select_one(".result__snippet")
        results.append({
            "title": anchor.get_text(" ", strip=True)[:300],
            "url": result_url[:1500],
            "snippet": snippet_node.get_text(" ", strip=True)[:700] if snippet_node else "",
            "source": "DuckDuckGo public HTML results",
            "search_page": final,
        })
    return results
