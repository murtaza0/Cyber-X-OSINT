"""Safe ingestion and matching for redacted analyst-provided exposure indexes.

Only identifier metadata is accepted. Passwords, credential pairs, tokens and
raw dump fields are rejected. Identifiers are keyed-HMACed before persistence.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import re
from urllib.parse import urlsplit

from app.core.config import settings

MAX_DATASET_BYTES = 5 * 1024 * 1024
MAX_DATASET_ROWS = 20_000
ALLOWED_COLUMNS = {"email", "username", "domain", "breach_name", "breach_date", "source_reference"}
FORBIDDEN_COLUMN_PARTS = ("password", "passwd", "credential", "secret", "token", "cookie", "session", "hash", "dump", "private_key")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


class DatasetValidationError(ValueError):
    pass


def _key() -> bytes:
    value = settings.exposure_hmac_key.strip()
    if len(value) < 32:
        raise DatasetValidationError("Configure EXPOSURE_HMAC_KEY with at least 32 characters before using Exposure Lab")
    return value.encode("utf-8")


def normalize_identifier(kind: str, value: str) -> str:
    value = (value or "").strip()
    if kind == "email":
        value = value.casefold()
        if not EMAIL_RE.fullmatch(value) or len(value) > 320:
            raise DatasetValidationError("Invalid email identifier in dataset")
    elif kind == "username":
        value = value.removeprefix("@").casefold()
        if not re.fullmatch(r"[a-z0-9_.-]{2,64}", value):
            raise DatasetValidationError("Invalid username identifier in dataset")
    elif kind == "domain":
        value = value.rstrip(".").casefold()
        if not DOMAIN_RE.fullmatch(value):
            raise DatasetValidationError("Invalid domain identifier in dataset")
    else:
        raise DatasetValidationError("Unsupported identifier type")
    return value


def identifier_hmac(kind: str, value: str) -> str:
    normalized = normalize_identifier(kind, value)
    return hmac.new(_key(), f"{kind}:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()


def mask_identifier(kind: str, value: str) -> str:
    normalized = normalize_identifier(kind, value)
    if kind == "email":
        local, domain = normalized.split("@", 1)
        return (local[:1] + "***@" + domain) if local else "***@" + domain
    if kind == "username":
        return normalized[:1] + "***" + normalized[-1:]
    return normalized


def _validate_reference(value: str) -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    if len(value) > 1000:
        raise DatasetValidationError("Source reference is too long")
    parsed = urlsplit(value)
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise DatasetValidationError("Source references must be HTTP(S) URLs or plain citation text")
    if parsed.scheme and (not parsed.hostname or parsed.username or parsed.password):
        raise DatasetValidationError("Invalid source reference URL")
    return value


def parse_redacted_csv(raw: bytes) -> tuple[list[dict], str]:
    if not raw:
        raise DatasetValidationError("The uploaded CSV is empty")
    if len(raw) > MAX_DATASET_BYTES:
        raise DatasetValidationError("Dataset exceeds the 5 MB upload limit")
    try:
        decoded = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DatasetValidationError("CSV must be UTF-8 encoded") from exc
    reader = csv.DictReader(io.StringIO(decoded, newline=""))
    if not reader.fieldnames:
        raise DatasetValidationError("CSV header row is required")
    headers = [str(name or "").strip().casefold() for name in reader.fieldnames]
    if len(headers) != len(set(headers)):
        raise DatasetValidationError("Duplicate CSV columns are not allowed")
    forbidden = [header for header in headers if any(part in header for part in FORBIDDEN_COLUMN_PARTS)]
    if forbidden:
        raise DatasetValidationError("Raw credential or secret columns are not accepted. Import a redacted identifier-only index.")
    unknown = [header for header in headers if header not in ALLOWED_COLUMNS]
    if unknown:
        raise DatasetValidationError("Unsupported CSV columns: " + ", ".join(unknown[:8]))
    identifier_cols = [col for col in ("email", "username", "domain") if col in headers]
    if not identifier_cols:
        raise DatasetValidationError("Include at least one identifier column: email, username or domain")

    records: list[dict] = []
    for row_number, row in enumerate(reader, start=2):
        if row_number > MAX_DATASET_ROWS + 1:
            raise DatasetValidationError(f"Dataset exceeds the {MAX_DATASET_ROWS:,}-row limit")
        clean = {str(k or "").strip().casefold(): (v or "").strip() for k, v in row.items() if k is not None}
        if not any(clean.get(col) for col in identifier_cols):
            continue
        item = {
            "indicators": [],
            "breach_name": (clean.get("breach_name") or "Unspecified incident")[:180],
            "breach_date": (clean.get("breach_date") or "")[:40] or None,
            "source_reference": _validate_reference(clean.get("source_reference", "")),
        }
        for kind in identifier_cols:
            value = clean.get(kind, "")
            if value:
                normalized = normalize_identifier(kind, value)
                item["indicators"].append({
                    "type": kind,
                    "hmac": identifier_hmac(kind, normalized),
                    "masked": mask_identifier(kind, normalized),
                })
        if item["indicators"]:
            records.append(item)
    if not records:
        raise DatasetValidationError("No valid identifier rows were found in the CSV")
    return records, hashlib.sha256(raw).hexdigest()
