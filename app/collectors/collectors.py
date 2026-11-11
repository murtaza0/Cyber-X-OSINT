import asyncio
import ipaddress
import json
import re
from urllib.parse import quote, urlsplit
from bs4 import BeautifulSoup
from .dns import lookup_records, reverse_dns
from .public_web import public_page, search_public_html
from .safety import normalize_http_url

MODULE_LABELS = {
    "username": "Username Intelligence", "email": "Email Intelligence", "phone": "Phone Intelligence",
    "domain": "Domain Intelligence", "ip": "IP Intelligence", "social": "Social Media Intelligence",
    "image": "Image Intelligence", "website": "Website Intelligence", "credential": "Credential Intelligence",
    "breach": "Breach Intelligence", "threat": "Threat Intelligence", "search": "Search Engine Intelligence",
    "document": "Document Intelligence", "github": "GitHub & Code Intelligence", "network": "Network Intelligence",
    "attack_surface": "Attack Surface Intelligence", "digital_footprint": "Digital Footprint", "correlation": "Intelligence Correlation",
}

def finding(module: str, kind: str, value: str, *, details=None, source_url=None, confidence=0.75):
    return {"module": module, "finding_type": kind, "value": str(value)[:5000], "details": details or {}, "source_url": source_url, "confidence": confidence, "verification_status": "observed" if source_url else "unverified"}

def _domain_for(target_type: str, target: str) -> str | None:
    if target_type == "domain": return target
    if target_type == "url": return urlsplit(normalize_http_url(target)).hostname
    if target_type == "email": return target.rsplit("@", 1)[-1]
    return None

async def collect_domain(target: str, target_type: str) -> list[dict]:
    domain = _domain_for(target_type, target)
    if not domain: return [finding("domain", "status", "No domain component available")]
    records = lookup_records(domain)
    results = [finding("domain", "dns_records", json.dumps(records, ensure_ascii=False), details={"domain": domain}, confidence=0.95)]
    root_txt = " ".join(records.get("TXT", [])).lower()
    dmarc_records = lookup_records(f"_dmarc.{domain}").get("TXT", [])
    has_spf = "v=spf1" in root_txt
    has_dmarc = any("v=dmarc1" in item.lower() for item in dmarc_records)
    results.append(finding(
        "domain", "email_domain_posture",
        json.dumps({"spf_record_present": has_spf, "dmarc_record_present": has_dmarc,
                    "dmarc_records": dmarc_records[:10],
                    "interpretation": "Presence checks only; record syntax, alignment and enforcement require separate review."},
                   ensure_ascii=False),
        details={"domain": domain}, confidence=0.85
    ))
    # Certificate transparency results are parsed from the public HTML page (not its JSON endpoint).
    try:
        response, final = await public_page(f"https://crt.sh/?q=%25.{quote(domain)}", max_bytes=2_000_000)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "lxml")
            candidates = set()
            for cell in soup.select("td"):
                raw = cell.get_text(" ", strip=True).lower()
                for item in re.findall(r"(?<![a-z0-9-])(?:[a-z0-9-]+\.)+" + re.escape(domain.lower()) + r"(?![a-z0-9-])", raw):
                    candidates.add(item.strip("."))
            names = sorted(candidates)[:300]
            results.append(finding("domain", "certificate_names", json.dumps(names), details={"count": len(names), "collection_mode": "public_html"}, source_url=final, confidence=0.85))
        else:
            results.append(finding("domain", "certificate_source_status", f"crt.sh HTML returned HTTP {response.status_code}", source_url=final, confidence=0.5))
    except Exception as exc:
        results.append(finding("domain", "source_error", f"Certificate HTML source unavailable: {str(exc)[:220]}", confidence=0.2))
    return results

async def collect_ip(target: str) -> list[dict]:
    ip = ipaddress.ip_address(target)
    out = [finding("ip", "ip_classification", f"{ip} ({'global' if ip.is_global else 'non-global'})", details={"version": ip.version, "is_global": ip.is_global}, confidence=1.0)]
    if not ip.is_global:
        return out
    ptr = reverse_dns(target)
    if ptr:
        out.append(finding("ip", "reverse_dns", ptr, confidence=0.9))
    try:
        response, final = await public_page(f"https://bgp.he.net/ip/{quote(target)}", max_bytes=1_000_000)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "lxml")
            title = soup.title.get_text(" ", strip=True) if soup.title else ""
            text = soup.get_text(" ", strip=True)
            asns = sorted(set(re.findall(r"\bAS\d{1,10}\b", text)))[:30]
            out.append(finding("ip", "public_routing_page", json.dumps({"title": title, "autonomous_systems": asns, "excerpt": text[:900]}, ensure_ascii=False), source_url=final, confidence=0.7))
    except Exception as exc:
        out.append(finding("ip", "source_status", f"Public routing page unavailable: {str(exc)[:180]}", confidence=0.2))
    return out

async def collect_website(target: str) -> list[dict]:
    url = normalize_http_url(target)
    try:
        # Shared helper validates public DNS, honours robots.txt and restricts redirects
        # to the original host before parsing the public page.
        response, final = await public_page(url, max_bytes=2_000_000, obey_robots=True)
    except PermissionError as exc:
        return [finding("website", "robots_policy", str(exc)[:400], confidence=1.0)]
    text = response.text
    soup = BeautifulSoup(text, "lxml")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    description = ""
    meta = soup.find("meta", attrs={"name": re.compile("description", re.I)})
    if meta: description = meta.get("content", "")[:1000]
    links = []
    host = urlsplit(final).hostname
    for tag in soup.find_all("a", href=True)[:200]:
        href = tag["href"].strip()
        if href.startswith(("http://", "https://")):
            links.append(href)
    tech = []
    server = response.headers.get("server")
    powered = response.headers.get("x-powered-by")
    if server: tech.append(f"Server: {server}")
    if powered: tech.append(f"X-Powered-By: {powered}")
    if "wp-content" in text: tech.append("Possible WordPress indicators")
    if "_next/" in text: tech.append("Possible Next.js indicators")
    if "__vite" in text: tech.append("Possible Vite indicators")
    return [
        finding("website", "page_title", title or "No title found", source_url=final, confidence=0.95),
        finding("website", "meta_description", description or "No meta description found", source_url=final, confidence=0.9),
        finding("website", "http_headers", json.dumps(dict(response.headers), ensure_ascii=False), source_url=final, confidence=0.95),
        finding("website", "technology_hints", json.dumps(tech), source_url=final, confidence=0.6),
        finding("website", "public_links", json.dumps(links[:100]), details={"count": len(links), "host": host}, source_url=final, confidence=0.75),
    ]

async def collect_github(username: str) -> list[dict]:
    url = f"https://github.com/{quote(username, safe='')}"
    try:
        response, final = await public_page(url, max_bytes=2_000_000)
    except Exception as exc:
        return [finding("github", "source_error", f"Public GitHub HTML unavailable: {str(exc)[:220]}", confidence=0.2)]
    if response.status_code == 404:
        return [finding("github", "profile_status", "No public GitHub profile found", source_url=final, confidence=0.85)]
    if response.status_code != 200:
        return [finding("github", "source_status", f"GitHub profile HTML returned HTTP {response.status_code}", source_url=final, confidence=0.5)]
    soup = BeautifulSoup(response.text, "lxml")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    description = soup.find("meta", attrs={"name": "description"})
    description_text = description.get("content", "")[:800] if description else ""
    og_image = soup.find("meta", attrs={"property": "og:image"})
    profile = {"username": username, "page_title": title, "description": description_text,
               "avatar_url": og_image.get("content") if og_image else None}
    repos = []
    for anchor in soup.select('a[href^="/' + username + '/"]'):
        href = anchor.get("href", "")
        parts = [part for part in href.split("?")[0].split("#")[0].split("/") if part]
        if len(parts) == 2 and parts[0].casefold() == username.casefold() and parts[1] not in {"followers", "following", "repositories", "projects", "packages", "stars"}:
            name = parts[1]
            if name not in {"issues", "pulls", "actions", "settings"}:
                repos.append({"name": name, "url": "https://github.com" + href.split("?")[0]})
    deduped = list({item["url"]: item for item in repos}.values())[:30]
    return [
        finding("github", "public_profile_html", json.dumps(profile, ensure_ascii=False), source_url=final, confidence=0.8),
        finding("github", "public_repositories_html", json.dumps(deduped, ensure_ascii=False), details={"count": len(deduped), "collection_mode": "public_html"}, source_url=final, confidence=0.7),
    ]

async def collect_username(username: str) -> list[dict]:
    sites = {
        "GitHub": f"https://github.com/{quote(username, safe='')}",
        "GitLab": f"https://gitlab.com/{quote(username, safe='')}",
        "Reddit": f"https://www.reddit.com/user/{quote(username, safe='')}/",
        "Keybase": f"https://keybase.io/{quote(username, safe='')}",
    }
    out = [finding("username", "username_search", username, confidence=1.0)]
    for name, url in sites.items():
        try:
            response, final = await public_page(url, max_bytes=1_000_000)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "lxml")
                title = soup.title.get_text(" ", strip=True) if soup.title else ""
                desc = soup.find("meta", attrs={"name": "description"})
                description = desc.get("content", "")[:400] if desc else ""
                out.append(finding("username", "public_profile_observed", json.dumps({"platform": name, "title": title, "description": description}, ensure_ascii=False), details={"platform": name, "http_status": response.status_code}, source_url=final, confidence=0.72))
            else:
                out.append(finding("username", "profile_status", f"{name}: HTTP {response.status_code}", details={"platform": name}, source_url=final, confidence=0.4))
        except PermissionError as exc:
            out.append(finding("username", "profile_skipped", f"{name}: {str(exc)[:180]}", details={"platform": name}, confidence=0.3))
        except Exception as exc:
            out.append(finding("username", "profile_source_error", f"{name}: {str(exc)[:180]}", details={"platform": name}, confidence=0.2))
    return out

async def collect_email(email: str) -> list[dict]:
    domain = email.rsplit("@", 1)[-1]
    records = lookup_records(domain)
    root_txt = " ".join(records.get("TXT", [])).lower()
    dmarc_records = lookup_records(f"_dmarc.{domain}").get("TXT", [])
    posture = {
        "spf_record_present": "v=spf1" in root_txt,
        "dmarc_record_present": any("v=dmarc1" in item.lower() for item in dmarc_records),
        "dmarc_records": dmarc_records[:10],
        "interpretation": "Presence checks only; syntax, alignment and enforcement require separate review."
    }
    search_links = [
        f"https://www.google.com/search?q=%22{quote(email)}%22",
        f"https://www.bing.com/search?q=%22{quote(email)}%22",
        f"https://duckduckgo.com/?q=%22{quote(email)}%22",
    ]
    return [
        finding("email", "email_identifier", email, confidence=1.0),
        finding("email", "domain_dns", json.dumps(records, ensure_ascii=False), details={"domain": domain}, confidence=0.9),
        finding("email", "email_domain_posture", json.dumps(posture, ensure_ascii=False), details={"domain": domain}, confidence=0.85),
        finding("email", "public_search_references", json.dumps(search_links), details={"note": "Open these public search queries manually; no mailbox probing was performed"}, confidence=0.5),
    ]

async def collect_phone(phone: str) -> list[dict]:
    digits = re.sub(r"\D", "", phone)
    country = "Unknown"
    prefix_map = {"92": "Pakistan", "1": "United States/Canada", "44": "United Kingdom", "91": "India", "971": "United Arab Emirates", "61": "Australia"}
    for prefix in sorted(prefix_map, key=len, reverse=True):
        if digits.startswith(prefix): country = prefix_map[prefix]; break
    return [finding("phone", "phone_identifier", phone, details={"normalized_digits": digits, "possible_country": country, "note": "Country estimate based on calling prefix; not carrier or subscriber verification"}, confidence=0.6)]

async def collect_search(target: str) -> list[dict]:
    results = await search_public_html(f'"{target}"', limit=8)
    return [finding("search", "public_html_search_results", json.dumps(results, ensure_ascii=False), details={"count": len(results), "collection_mode": "public_html", "absence_of_results_is_not_proof_of_absence": True}, source_url="https://html.duckduckgo.com/html/" if results else None, confidence=0.65 if results else 0.35)]

async def collect_breach(target: str) -> list[dict]:
    results = await search_public_html(f'"{target}" (breach OR "security incident" OR exposure OR notification)', limit=8)
    return [finding("breach", "public_incident_references", json.dumps(results, ensure_ascii=False), details={"reference_count": len(results), "collection_mode": "public_html", "note": "Publicly indexed incident references only; this does not establish that an account or password appeared in a breach. No credential dumps are accessed."}, source_url="https://html.duckduckgo.com/html/" if results else None, confidence=0.65 if results else 0.35)]

async def collect_threat(target: str) -> list[dict]:
    try:
        response, final = await public_page(f"https://urlhaus.abuse.ch/browse.php?search={quote(target)}", max_bytes=1_500_000)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "lxml")
            excerpt = soup.get_text(" ", strip=True)[:1800]
            links = [{"text": a.get_text(" ", strip=True)[:180], "url": a.get("href", "")[:700]} for a in soup.select("a[href]") if "urlhaus.abuse.ch" in a.get("href", "")][:30]
            return [finding("threat", "urlhaus_public_html", json.dumps({"excerpt": excerpt, "links": links}, ensure_ascii=False), source_url=final, confidence=0.65)]
        return [finding("threat", "source_status", f"URLhaus HTML returned HTTP {response.status_code}", source_url=final, confidence=0.35)]
    except Exception as exc:
        return [finding("threat", "source_error", f"URLhaus public HTML unavailable: {str(exc)[:200]}", confidence=0.2)]

async def collect_network(target: str, target_type: str) -> list[dict]:
    if target_type == "cidr":
        network = ipaddress.ip_network(target, strict=False)
        return [finding("network", "network_range", json.dumps({
            "cidr": str(network), "version": network.version,
            "network_address": str(network.network_address),
            "broadcast_address": str(network.broadcast_address),
            "prefix_length": network.prefixlen, "num_addresses": network.num_addresses,
            "is_global": network.is_global,
            "note": "Range metadata only; no host discovery or port scanning was performed."
        }), details={"range": str(network)}, confidence=1.0)]
    if target_type in {"domain", "url"}:
        domain = _domain_for(target_type, target)
        return [finding("network", "network_dns_map", json.dumps(lookup_records(domain), ensure_ascii=False), details={"domain": domain}, confidence=0.9)]
    if target_type == "ip":
        return await collect_ip(target)
    return [finding("network", "network_status", "Network module requires a domain, URL, or IP target", confidence=0.4)]

async def collect_module(module: str, target: str, target_type: str) -> list[dict]:
    if module == "domain": return await collect_domain(target, target_type)
    if module == "ip": return await collect_ip(target)
    if module == "website":
        if target_type in {"url", "domain"}: return await collect_website(target)
        return [finding(module, "not_applicable", "Website module requires a URL or domain", confidence=0.4)]
    if module == "github":
        return await collect_github(target.lstrip("@"))
    if module == "username": return await collect_username(target.lstrip("@"))
    if module == "email": return await collect_email(target)
    if module == "phone": return await collect_phone(target)
    if module == "search": return await collect_search(target)
    if module == "breach": return await collect_breach(target)
    if module == "threat": return await collect_threat(target)
    if module == "network": return await collect_network(target, target_type)
    if module == "attack_surface":
        if target_type in {"domain", "url"}:
            output = await collect_domain(target, target_type)
            output.extend(await collect_website(target))
            return [finding("attack_surface", item["finding_type"], item["value"], details=item.get("details"), source_url=item.get("source_url"), confidence=item.get("confidence", 0.5)) for item in output]
        return [finding(module, "not_applicable", "Passive attack-surface collection requires a domain or URL", confidence=0.4)]
    if module == "social":
        results = await search_public_html(f'"{target}" (site:linkedin.com OR site:instagram.com OR site:x.com OR site:facebook.com)', limit=8)
        return [finding(module, "public_social_search_results", json.dumps(results, ensure_ascii=False), details={"count": len(results), "collection_mode": "public_html", "note": "Only public indexed result pages; private posts and login-gated content are not accessed."}, source_url="https://html.duckduckgo.com/html/" if results else None, confidence=0.65 if results else 0.35)]
    if module == "digital_footprint":
        return [finding(module, "footprint_seed", target, details={"target_type": target_type, "note": "Related entities will be added as collectors return evidence"}, confidence=0.6)]
    if module == "correlation":
        return [finding(module, "correlation_status", "Correlation runs automatically after findings are stored", confidence=0.8)]
    if module in {"credential", "image", "document"}:
        return [finding(module, "manual_input_required", f"{module} module uses authorized manual records or file uploads", confidence=0.7)]
    return [finding(module, "module_status", "Module registered; no source adapter configured yet", confidence=0.3)]
