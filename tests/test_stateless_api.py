import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.api.stateless_routes import require_auth
import app.api.stateless_routes as stateless


@pytest.fixture
def client():
    app.dependency_overrides[require_auth] = lambda: None
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_health_declares_memory_only_storage(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["storage"] == "memory_only"


def test_module_catalog_excludes_credential_storage(client):
    response = client.get("/api/v1/modules")
    assert response.status_code == 200
    ids = {item["id"] for item in response.json()}
    assert "domain" in ids
    assert "credential" not in ids
    assert "image" not in ids
    assert "document" not in ids


def test_scan_returns_transient_results(client, monkeypatch):
    async def fake_collect(module, target, target_type):
        return [{
            "module": module,
            "finding_type": "test_observation",
            "value": f"{target_type}:{target}",
            "details": {"source": "synthetic-test"},
            "source_url": "https://example.test/",
            "confidence": 0.9,
            "verification_status": "observed",
        }]

    monkeypatch.setattr(stateless, "collect_module", fake_collect)
    response = client.post(
        "/api/v1/scan",
        json={"target": "example.com", "modules": ["domain"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["storage"] == "memory_only"
    assert body["normalized_target"] == "example.com"
    assert body["summary"]["findings"] == 1
    assert body["findings"][0]["finding_type"] == "test_observation"


def test_scan_rejects_empty_supported_module_selection(client):
    response = client.post(
        "/api/v1/scan",
        json={"target": "example.com", "modules": ["credential", "image"]},
    )
    assert response.status_code == 400
