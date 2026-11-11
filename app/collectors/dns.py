import socket
import ipaddress
from typing import Any
try:
    import dns.resolver
except Exception:
    dns = None

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

def lookup_records(domain: str) -> dict[str, list[str] | str]:
    result: dict[str, Any] = {}
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4
        for kind in RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, kind, raise_on_no_answer=False)
                if answers.rrset:
                    result[kind] = [r.to_text() for r in answers]
            except Exception:
                result[kind] = []
    except ImportError:
        try:
            result["A"] = sorted({item[4][0] for item in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM) if ipaddress.ip_address(item[4][0]).version == 4})
        except Exception as exc:
            result["error"] = str(exc)
    return result

def reverse_dns(address: str) -> str | None:
    try:
        return socket.gethostbyaddr(address)[0]
    except Exception:
        return None
