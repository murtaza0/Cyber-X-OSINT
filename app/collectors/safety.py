import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

class UnsafeTarget(ValueError):
    pass

def normalize_http_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise UnsafeTarget("URL is empty")
    if "://" not in value:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTarget("URL contains an invalid hostname or port") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeTarget("Only HTTP and HTTPS are supported")
    if not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeTarget("A hostname is required; URL credentials are not allowed")
    expected_port = 80 if parsed.scheme.lower() == "http" else 443
    if port is not None and port != expected_port:
        raise UnsafeTarget("Non-standard ports are disabled")
    raw_host = parsed.hostname.rstrip(".")
    try:
        host_ip = ipaddress.ip_address(raw_host)
        host = f"[{host_ip.compressed}]" if host_ip.version == 6 else str(host_ip)
    except ValueError:
        try:
            host = raw_host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise UnsafeTarget("Hostname is not valid IDNA") from exc
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))

def validate_public_host(host: str) -> list[str]:
    try:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTarget(f"DNS resolution failed for {host}") from exc
    addresses = sorted({item[4][0].split("%")[0] for item in answers})
    if not addresses:
        raise UnsafeTarget("Hostname did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise UnsafeTarget(f"Target resolves to a non-public address: {ip}")
    return addresses

def safe_url_host(url: str) -> str:
    normalized = normalize_http_url(url)
    host = urlsplit(normalized).hostname
    validate_public_host(host)
    return normalized
