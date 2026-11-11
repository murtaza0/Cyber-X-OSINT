"""Offline password hygiene and public incident-reference search; no third-party APIs."""
from __future__ import annotations

import re
from pathlib import Path

from app.collectors.public_web import search_public_html


COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "12345", "1234567", "password", "password1",
    "admin", "admin123", "qwerty", "qwerty123", "abc123", "111111", "000000",
    "iloveyou", "welcome", "letmein", "monkey", "dragon", "football", "login",
    "passw0rd", "p@ssw0rd", "changeme", "root", "toor", "secret", "summer2024",
    "pakistan", "pakistan123", "murtaza", "murtaza123", "123123", "654321",
}


def _looks_predictable(password: str) -> bool:
    lowered = password.casefold()
    if lowered in COMMON_PASSWORDS:
        return True
    if re.fullmatch(r"(\d)\1{5,}", password):
        return True
    if re.fullmatch(r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432)\d*", password):
        return True
    return False


async def check_password_exposure(password: str) -> dict:
    """Evaluate only local common-password heuristics; never send/store the candidate."""
    if not password:
        raise ValueError("Password must not be empty")
    common = _looks_predictable(password)
    classes = sum((
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ))
    return {
        "is_common": common,
        "is_exposed": common,
        "prevalence_count": None,
        "method": "offline local weak-password heuristics",
        "provider": "built-in local checks",
        "length": len(password),
        "character_classes": classes,
        "privacy": "The candidate was evaluated in-process; no external request was made and the candidate was not stored.",
        "scope_warning": "This is not a leaked-password corpus lookup and cannot confirm historical breach exposure.",
    }


async def lookup_email_breaches(email: str) -> list[dict]:
    """Find public incident disclosures indexed on the open web; never fetch dumps."""
    query = f'"{email.strip()}" (breach OR "security incident" OR exposure OR notification)'
    return await search_public_html(query, limit=8)
