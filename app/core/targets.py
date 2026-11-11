import ipaddress
import re
from urllib.parse import urlsplit

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
HASH_PATTERNS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")

def detect_target(raw: str) -> tuple[str, str]:
    value = raw.strip()
    if not value:
        raise ValueError("Target is empty")
    if value.lower().startswith(("http://", "https://")):
        try:
            p = urlsplit(value)
            _ = p.port
        except ValueError as exc:
            raise ValueError("URL contains an invalid hostname or port") from exc
        if p.scheme.lower() not in {"http", "https"} or not p.hostname or p.username or p.password:
            raise ValueError("URL must use HTTP(S), include a hostname and contain no embedded credentials")
        return "url", value
    if EMAIL_RE.match(value):
        return "email", value.lower()
    if "/" in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
            return "cidr", str(network)
        except ValueError:
            pass
    try:
        ip = ipaddress.ip_address(value)
        return "ip", str(ip)
    except ValueError:
        pass
    if len(value) in HASH_PATTERNS and all(c in "0123456789abcdefABCDEF" for c in value):
        return "file_hash", value.lower()
    if DOMAIN_RE.match(value):
        return "domain", value.rstrip(".").lower()
    if value.startswith("+") or (value.replace(" ", "").replace("-", "").isdigit() and len(value) >= 7):
        return "phone", value
    if value.startswith("@"):
        return "username", value[1:]
    if re.fullmatch(r"[A-Za-z0-9_.-]{2,64}", value):
        return "username", value
    return "name", value

MODULES = [
    "username", "email", "phone", "domain", "ip", "social", "image", "website",
    "credential", "breach", "threat", "search", "document", "github", "network",
    "attack_surface", "digital_footprint", "correlation"
]

def modules_for_target(target_type: str) -> list[str]:
    mapping = {
        "email": ["email", "breach", "search", "digital_footprint", "correlation"],
        "username": ["username", "github", "social", "search", "digital_footprint", "correlation"],
        "phone": ["phone", "search", "digital_footprint", "correlation"],
        "domain": ["domain", "website", "network", "attack_surface", "threat", "search", "correlation"],
        "url": ["website", "domain", "search", "attack_surface", "correlation"],
        "ip": ["ip", "network", "threat", "correlation"],
        "cidr": ["network", "threat", "search", "correlation"],
        "file_hash": ["threat", "search", "correlation"],
        "name": ["search", "social", "digital_footprint", "correlation"],
    }
    return mapping.get(target_type, ["search", "correlation"])
