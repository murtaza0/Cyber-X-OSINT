"""Owner-configured, read-only PostgreSQL connectors for scoped exposure checks."""
from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.core.config import settings

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class AuthorizedDatabaseError(RuntimeError):
    pass


def configured_databases() -> dict[str, dict[str, Any]]:
    raw = settings.authorized_databases_json.strip() or "{}"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthorizedDatabaseError("AUTHORIZED_DATABASES_JSON is not valid JSON") from exc
    if not isinstance(data, dict):
        raise AuthorizedDatabaseError("AUTHORIZED_DATABASES_JSON must be a JSON object")

    valid: dict[str, dict[str, Any]] = {}
    for name, config in data.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", name):
            continue
        if not isinstance(config, dict) or not isinstance(config.get("url"), str):
            continue
        tables = config.get("tables", {})
        if not isinstance(tables, dict):
            continue
        safe_tables: dict[str, list[str]] = {}
        for table, columns in tables.items():
            if not isinstance(table, str) or not IDENTIFIER_RE.fullmatch(table) or not isinstance(columns, list):
                continue
            safe_columns = [col for col in columns if isinstance(col, str) and IDENTIFIER_RE.fullmatch(col)]
            if safe_columns:
                safe_tables[table] = list(dict.fromkeys(safe_columns))
        if not safe_tables:
            continue
        try:
            parsed = make_url(config["url"])
        except Exception:
            continue
        # Restrict this connector to PostgreSQL; credentials/DSNs remain in server env only.
        if parsed.drivername != "postgresql+psycopg" or not parsed.host or not parsed.database:
            continue
        valid[name] = {"url": config["url"], "tables": safe_tables, "description": str(config.get("description", ""))[:300]}
    return valid


def public_database_catalog() -> list[dict]:
    return [
        {"name": name, "description": cfg["description"], "tables": [{"name": table, "columns": cols} for table, cols in cfg["tables"].items()]}
        for name, cfg in configured_databases().items()
    ]


def count_exact_matches(connector_name: str, table: str, column: str, value: str) -> int:
    connectors = configured_databases()
    config = connectors.get(connector_name)
    if not config:
        raise AuthorizedDatabaseError("Authorized database connector is not configured")
    allowed_columns = config["tables"].get(table)
    if not allowed_columns or column not in allowed_columns:
        raise AuthorizedDatabaseError("Table or column is outside the connector's configured allowlist")

    # Identifiers are selected only from the server-side allowlist; values are bound parameters.
    engine = create_engine(
        config["url"],
        pool_pre_ping=True,
        pool_size=1,
        max_overflow=0,
        connect_args={"connect_timeout": 5, "options": "-c statement_timeout=5000"},
    )
    try:
        preparer = engine.dialect.identifier_preparer
        quoted_table = preparer.quote(table)
        quoted_column = preparer.quote(column)
        with engine.connect() as connection:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            result = connection.execute(
                text(f"SELECT COUNT(*) FROM {quoted_table} WHERE {quoted_column} = :lookup_value"),
                {"lookup_value": value},
            )
            return int(result.scalar_one())
    finally:
        engine.dispose()
