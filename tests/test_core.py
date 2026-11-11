import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from cryptography.fernet import Fernet
from app.db.database import Base, get_db
from app.models.models import CredentialRecord, AuditLog
from app.core.targets import detect_target, modules_for_target
from app.core.security import encrypt_secret, decrypt_secret
from app.main import app


def test_target_detection():
    assert detect_target("analyst@example.org")[0] == "email"
    assert detect_target("203.0.113.10")[0] == "ip"
    assert detect_target("192.0.2.0/24") == ("cidr", "192.0.2.0/24")
    assert detect_target("example.org")[0] == "domain"
    assert detect_target("https://example.org/path")[0] == "url"
    assert detect_target("@sample_user")[0] == "username"
    assert "domain" in modules_for_target("domain")


def test_credential_encryption_round_trip():
    secret = "authorized-lab-example-only"
    encrypted = encrypt_secret(secret)
    assert encrypted != secret
    assert decrypt_secret(encrypted) == secret


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, client=("127.0.0.1", 12345)) as test_client:
        yield test_client, TestingSession
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def test_investigation_and_credential_show_hide_audit(client):
    http, TestingSession = client
    response = http.post("/api/v1/investigations", json={"name": "Authorized Lab Case", "description": "Local test fixture"})
    assert response.status_code == 200
    case_id = response.json()["id"]

    target = http.post(f"/api/v1/investigations/{case_id}/targets", json={"value": "analyst@example.org"})
    assert target.status_code == 200
    assert target.json()["type"] == "email"

    password = "not-a-real-password-fixture"
    created = http.post(f"/api/v1/investigations/{case_id}/credentials", json={
        "identifier_type": "email",
        "identifier_reference": "analyst@example.org",
        "password": password,
        "authorization_context": "Fictional authorized test fixture",
        "target_id": target.json()["id"],
    })
    assert created.status_code == 200
    credential_id = created.json()["id"]
    assert password not in created.text

    listed = http.get(f"/api/v1/investigations/{case_id}/credentials")
    assert listed.status_code == 200
    assert password not in listed.text

    with TestingSession() as db:
        record = db.get(CredentialRecord, credential_id)
        assert record.encrypted_password != password

    revealed = http.post(f"/api/v1/credentials/{credential_id}/reveal")
    assert revealed.status_code == 200
    assert revealed.json()["password"] == password
    assert revealed.headers["cache-control"].startswith("no-store")

    with TestingSession() as db:
        events = db.scalars(select(AuditLog).where(AuditLog.action == "credential.revealed")).all()
        assert len(events) == 1
        assert password not in (events[0].detail or "")

    report = http.get(f"/api/v1/investigations/{case_id}/report?format=json")
    assert report.status_code == 200
    assert password not in report.text
    html_report = http.get(f"/api/v1/investigations/{case_id}/report?format=html")
    assert html_report.status_code == 200
    assert password not in html_report.text
    pdf_report = http.get(f"/api/v1/investigations/{case_id}/report?format=pdf")
    assert pdf_report.status_code == 200 and pdf_report.content.startswith(b"%PDF")


def test_collection_job_and_pdf_export(client, monkeypatch):
    http, TestingSession = client
    monkeypatch.setattr("app.services.collection.SessionLocal", TestingSession)
    case = http.post("/api/v1/investigations", json={"name": "Username Collector Test"}).json()
    target = http.post(f"/api/v1/investigations/{case['id']}/targets", json={"value": "sample_user"}).json()
    queued = http.post(f"/api/v1/investigations/{case['id']}/targets/{target['id']}/collect", json={"modules": ["username"]})
    assert queued.status_code == 200
    job = http.get(f"/api/v1/jobs/{queued.json()['job_id']}")
    assert job.status_code == 200
    assert job.json()["status"] == "completed"
    assert job.json()["findings_count"] >= 1
    report = http.get(f"/api/v1/investigations/{case['id']}/report?format=pdf")
    assert report.status_code == 200
    assert report.headers["content-type"].startswith("application/pdf")
    assert report.content.startswith(b"%PDF")


def test_upload_and_password_validation_redaction(client):
    http, _ = client
    case = http.post("/api/v1/investigations", json={"name": "File Evidence Test"}).json()
    upload = http.post(
        f"/api/v1/investigations/{case['id']}/uploads",
        files={"file": ("analyst-notes.txt", b"authorized sample evidence", "text/plain")},
    )
    assert upload.status_code == 200
    assert len(upload.json()["sha256"]) == 64

    oversized_secret = "X" * 5000
    invalid = http.post(f"/api/v1/investigations/{case['id']}/credentials", json={
        "identifier_type": "email",
        "identifier_reference": "analyst@example.org",
        "password": oversized_secret,
        "authorization_context": "Fictional authorized test fixture",
    })
    assert invalid.status_code == 422
    assert oversized_secret not in invalid.text


def test_api_token_gate(client, monkeypatch):
    from app.core.config import settings
    http, _ = client
    monkeypatch.setattr(settings, "api_token", "local-test-token")
    denied = http.get("/api/v1/dashboard")
    assert denied.status_code == 401
    allowed = http.get("/api/v1/dashboard", headers={"X-API-Token": "local-test-token"})
    assert allowed.status_code == 200


def test_source_url_rejects_javascript(client):
    http, _ = client
    response = http.post("/api/v1/sources", json={
        "name": "Unsafe Link", "category": "test", "source_url": "javascript:alert(1)",
        "description": "This should be rejected",
    })
    assert response.status_code == 400



def test_remote_api_access_requires_token(client):
    from app.core.config import settings
    http, _ = client
    previous = settings.api_token
    settings.api_token = ""
    try:
        remote = TestClient(app, client=("198.51.100.20", 12345))
        response = remote.get("/api/v1/dashboard")
        assert response.status_code == 401
        assert "API_TOKEN" in response.json()["detail"]
    finally:
        settings.api_token = previous


def test_url_normalization_rejects_invalid_ports_and_preserves_ipv6():
    from app.collectors.safety import normalize_http_url, UnsafeTarget
    with pytest.raises(UnsafeTarget):
        normalize_http_url("https://example.org:not-a-port/")
    assert normalize_http_url("https://[2606:4700:4700::1111]/") == "https://[2606:4700:4700::1111]/"


def test_private_ip_is_not_a_public_collection_target():
    from app.collectors.safety import validate_public_host, UnsafeTarget
    with pytest.raises(UnsafeTarget):
        validate_public_host("127.0.0.1")



def test_domain_collector_emits_spf_dmarc_posture(monkeypatch):
    from app.collectors import collectors
    monkeypatch.setattr(collectors, "lookup_records", lambda name: {
        "TXT": ["v=spf1 include:_spf.example.org -all"] if name == "example.org" else ["v=DMARC1; p=reject"]
    })
    async def fake_public_page(url, **kwargs):
        class Response:
            status_code = 404
            text = ""
        return Response(), url
    monkeypatch.setattr(collectors, "public_page", fake_public_page)
    import asyncio, json
    results = asyncio.run(collectors.collect_domain("example.org", "domain"))
    posture = next(x for x in results if x["finding_type"] == "email_domain_posture")
    data = json.loads(posture["value"])
    assert data["spf_record_present"] is True
    assert data["dmarc_record_present"] is True


def test_ipv6_entity_extraction():
    from app.services.correlation import _extract_entities
    assert ("ip", "2001:db8::1") in list(_extract_entities("Observed endpoint 2001:db8::1"))



def test_collection_job_marks_all_module_failures_failed(client, monkeypatch):
    import app.services.collection as collection
    http, TestingSession = client
    monkeypatch.setattr(collection, "SessionLocal", TestingSession)
    async def fail_collector(module, target, target_type):
        raise RuntimeError("fixture source unavailable")
    monkeypatch.setattr(collection, "collect_module", fail_collector)
    case = http.post("/api/v1/investigations", json={"name": "Failed Collection Test"}).json()
    target = http.post(f"/api/v1/investigations/{case['id']}/targets", json={"value": "sample_user"}).json()
    queued = http.post(f"/api/v1/investigations/{case['id']}/targets/{target['id']}/collect", json={"modules": ["username"]})
    job = http.get(f"/api/v1/jobs/{queued.json()['job_id']}")
    assert job.json()["status"] == "failed"
    assert job.json()["findings_count"] == 1
    assert job.json()["error"] == "Failed modules: username"





def test_cidr_network_collector_is_metadata_only():
    import asyncio, json
    from app.collectors.collectors import collect_network
    result = asyncio.run(collect_network("192.0.2.0/24", "cidr"))
    details = json.loads(result[0]["value"])
    assert details["prefix_length"] == 24
    assert details["num_addresses"] == 256
    assert "no host discovery" in details["note"].lower()



def test_target_detection_rejects_malformed_url_and_accepts_uppercase_scheme():
    from app.core.targets import detect_target
    assert detect_target("HTTPS://example.org/path")[0] == "url"
    with pytest.raises(ValueError):
        detect_target("https://example.org:not-a-port/")


def test_password_exposure_check_never_persists_candidate(client, monkeypatch):
    import app.api.routes as routes
    from app.models.models import Finding
    http, TestingSession = client
    case = http.post("/api/v1/investigations", json={"name": "Password Hygiene Check"}).json()
    candidate = "not-a-real-secret-fixture"

    async def fake_check(value):
        assert value == candidate
        return {
            "is_common": True,
            "is_exposed": True,
            "prevalence_count": None,
            "method": "offline local weak-password heuristics",
            "provider": "built-in local checks",
            "length": len(value),
            "character_classes": 3,
            "privacy": "The candidate was evaluated in-process; no external request was made and the candidate was not stored.",
            "scope_warning": "This is not a leaked-password corpus lookup and cannot confirm historical breach exposure.",
        }

    monkeypatch.setattr(routes, "check_password_exposure", fake_check)
    response = http.post(f"/api/v1/investigations/{case['id']}/password-exposure-check", json={
        "password": candidate, "authorization_context": "Owner-approved password hygiene check"
    })
    assert response.status_code == 200
    assert response.json()["is_exposed"] is True
    assert response.json()["prevalence_count"] is None
    assert response.json()["candidate_stored"] is False
    assert "no external request" in response.json()["privacy"].lower()
    assert candidate not in response.text

    with TestingSession() as db:
        finding = db.scalars(select(Finding).where(Finding.finding_type == "password_exposure_check")).one()
        assert candidate not in finding.value
        assert candidate not in str(finding.details)
        assert candidate not in str(finding.details.get("privacy", ""))


def test_public_breach_reference_lookup_requires_email_target_and_records_metadata(client, monkeypatch):
    import app.api.routes as routes
    from app.models.models import Finding
    http, TestingSession = client
    case = http.post("/api/v1/investigations", json={"name": "Authorized Breach Review"}).json()
    email_target = http.post(f"/api/v1/investigations/{case['id']}/targets", json={"value": "owner@example.org"}).json()

    async def fake_lookup(email):
        assert email == "owner@example.org"
        return [{"title": "Example public disclosure", "url": "https://example.org/report", "snippet": "A synthetic incident reference.", "source": "fixture", "search_page": "https://html.duckduckgo.com/html/"}]

    monkeypatch.setattr(routes, "lookup_email_breaches", fake_lookup)
    response = http.post(f"/api/v1/investigations/{case['id']}/targets/{email_target['id']}/breach-check", json={
        "authorization_context": "Account owner explicitly approved this lookup"
    })
    assert response.status_code == 200
    assert response.json()["breach_count"] == 1
    assert response.json()["credential_material_collected"] is False
    with TestingSession() as db:
        row = db.scalars(select(Finding).where(Finding.finding_type == "public_breach_references")).one()
        assert row.details["references"][0]["title"] == "Example public disclosure"
        assert row.details["credential_material_collected"] is False


def test_authorized_database_lookup_returns_count_only(client, monkeypatch):
    import app.api.routes as routes
    http, _ = client
    case = http.post("/api/v1/investigations", json={"name": "Authorized DB Scope"}).json()
    target = http.post(f"/api/v1/investigations/{case['id']}/targets", json={"value": "owner@example.org"}).json()
    monkeypatch.setattr(routes, "count_exact_matches", lambda connector, table, column, value: 2)
    response = http.post(f"/api/v1/investigations/{case['id']}/database-lookups", json={
        "connector_name": "asset_inventory", "table": "users", "column": "email", "target_id": target["id"],
        "authorization_context": "Written approval from database owner ENG-1234"
    })
    assert response.status_code == 200
    assert response.json()["match_count"] == 2
    assert response.json()["row_data_returned"] is False


def test_authorized_database_config_requires_postgresql_and_identifier_allowlist(monkeypatch):
    import json
    from app.core.config import settings
    from app.services.authorized_database import configured_databases
    original = settings.authorized_databases_json
    settings.authorized_databases_json = json.dumps({
        "approved-db": {
            "url": "postgresql+psycopg://readonly:secret@db.example.test:5432/assets",
            "tables": {"users": ["email", "username", "bad-column;DROP TABLE users"]},
        },
        "unsafe-sqlite": {"url": "sqlite:////tmp/test.db", "tables": {"users": ["email"]}},
    })
    try:
        cfg = configured_databases()
        assert list(cfg) == ["approved-db"]
        assert cfg["approved-db"]["tables"] == {"users": ["email", "username"]}
        assert "secret" not in str(public_catalog := [{"name": key, "tables": value["tables"]} for key, value in cfg.items()])
    finally:
        settings.authorized_databases_json = original


def test_health_version_and_security_headers(client):
    http, _ = client
    health = http.get("/health")
    assert health.status_code == 200
    assert health.json()["version"] == "1.5.0"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in health.headers["content-security-policy"]


def test_password_hygiene_service_is_local_only():
    import asyncio
    from app.services.breach_intel import check_password_exposure
    weak = asyncio.run(check_password_exposure("password"))
    strong = asyncio.run(check_password_exposure("R4nd0m!local-only-example-value"))
    assert weak["is_common"] is True
    assert strong["is_common"] is False
    assert "no external request" in weak["privacy"].lower()
    assert "not a leaked-password corpus lookup" in weak["scope_warning"].lower()


def test_redacted_exposure_dataset_import_and_match(client, monkeypatch):
    from app.core.config import settings
    from app.models.models import ExposureIndicator, ExposureDataset
    http, TestingSession = client
    monkeypatch.setattr(settings, "exposure_hmac_key", "test-hmac-key-that-is-at-least-32-characters-long")

    case = http.post("/api/v1/investigations", json={"name": "Exposure Index Test"}).json()
    target = http.post(f"/api/v1/investigations/{case['id']}/targets", json={"value": "alice@example.test"}).json()
    csv_data = (
        "email,username,domain,breach_name,breach_date,source_reference\n"
        "alice@example.test,alice,example.test,Synthetic Test,2026-04-01,https://example.test/report\n"
    ).encode()
    imported = http.post(
        "/api/v1/exposure-datasets",
        data={"name": "Synthetic index", "source_label": "FYP fixture", "description": "Synthetic test data"},
        files={"file": ("index.csv", csv_data, "text/csv")},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["row_count"] == 1
    assert imported.json()["indicator_count"] == 3

    checked = http.post(f"/api/v1/investigations/{case['id']}/exposure-check", json={
        "target_id": target["id"],
        "authorization_context": "Synthetic university FYP test dataset with approval",
    })
    assert checked.status_code == 200, checked.text
    assert checked.json()["match_count"] == 1
    assert checked.json()["matches"][0]["breach_name"] == "Synthetic Test"

    with TestingSession() as db:
        indicator = db.query(ExposureIndicator).filter_by(indicator_type="email").one()
        assert indicator.identifier_hmac != "alice@example.test"
        assert indicator.masked_identifier == "a***@example.test"
        assert db.query(ExposureDataset).count() == 1


def test_exposure_import_rejects_password_dump_columns(client, monkeypatch):
    from app.core.config import settings
    http, _ = client
    monkeypatch.setattr(settings, "exposure_hmac_key", "test-hmac-key-that-is-at-least-32-characters-long")
    bad_csv = b"email,password,breach_name\nalice@example.test,plaintext-secret,Test\n"
    response = http.post(
        "/api/v1/exposure-datasets",
        data={"name": "Must reject", "source_label": "Untrusted fixture"},
        files={"file": ("dump.csv", bad_csv, "text/csv")},
    )
    assert response.status_code == 400
    assert "Raw credential" in response.json()["detail"]
    assert "plaintext-secret" not in response.text


def test_exposure_import_requires_hmac_key(client, monkeypatch):
    from app.core.config import settings
    http, _ = client
    monkeypatch.setattr(settings, "exposure_hmac_key", "")
    csv_data = b"email,breach_name\nalice@example.test,Synthetic\n"
    response = http.post(
        "/api/v1/exposure-datasets",
        data={"name": "No key", "source_label": "Test"},
        files={"file": ("index.csv", csv_data, "text/csv")},
    )
    assert response.status_code == 503
    assert "EXPOSURE_HMAC_KEY" in response.json()["detail"]


def test_vercel_startup_rejects_ephemeral_sqlite(monkeypatch):
    import app.main as main_module
    monkeypatch.setattr(main_module, "IS_VERCEL", True)
    monkeypatch.setattr(main_module, "DATABASE_URL", "sqlite:////tmp/cyberx-test.db")
    with pytest.raises(RuntimeError, match="persistent PostgreSQL DATABASE_URL"):
        with TestClient(main_module.app):
            pass
