from pathlib import Path

from fastapi.testclient import TestClient

from attack_flow_api.main import create_app


def _build_client(monkeypatch, tmp_path: Path) -> TestClient:
    data_dir = tmp_path / "data"
    providers_path = tmp_path / "providers.yml"
    providers_path.write_text(
        """
providers:
  - provider_id: default-openai
    provider_type: openai
    enabled: true
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
    default_model: gpt-4.1-mini
    allowed_models:
      - gpt-4.1-mini
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("APP_NAME", "attack-flow-api")
    monkeypatch.setenv("API_PREFIX", "/api/v1")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("SQLITE_PATH", str(data_dir / "attack-flow.db"))
    monkeypatch.setenv("UPLOAD_DIR", str(data_dir / "uploads"))
    monkeypatch.setenv("ARTIFACT_DIR", str(data_dir / "artifacts"))
    monkeypatch.setenv("PROVIDERS_CONFIG_PATH", str(providers_path))

    return TestClient(create_app())


def test_health_endpoint_returns_200_with_request_id(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/health")

    payload = response.json()
    assert response.status_code == 200
    assert payload["status"] == "ok"
    assert payload["service"] == "attack-flow-api"
    assert payload["version"] == "0.1.0"
    assert isinstance(payload["time"], str)
    assert payload["request_id"]


def test_status_endpoint_returns_200_with_lightweight_operational_fields(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/status")

    payload = response.json()
    assert response.status_code == 200
    assert payload["status"] == "ok"
    assert payload["database"] == "ok"
    assert payload["storage"] == "ok"
    assert payload["providers"]["configured_count"] == 1
    assert payload["queue"]["active_jobs"] == 0
    assert payload["queue"]["pending_jobs"] == 0
    assert payload["request_id"]


def test_providers_endpoint_returns_safe_provider_metadata(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/providers")

    payload = response.json()
    assert response.status_code == 200
    assert payload["request_id"]
    assert len(payload["providers"]) == 1
    provider = payload["providers"][0]
    assert provider == {
        "id": "default-openai",
        "type": "openai",
        "enabled": True,
        "default_model": "gpt-4.1-mini",
        "models": ["gpt-4.1-mini"],
    }
    assert "api_key_env" not in provider
    assert "base_url" not in provider


def test_endpoints_are_wired_under_api_v1_prefix(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        assert client.get("/health").status_code == 404
        assert client.get("/status").status_code == 404
        assert client.get("/providers").status_code == 404
        assert client.get("/api/v1/health").status_code == 200
        assert client.get("/api/v1/status").status_code == 200
        assert client.get("/api/v1/providers").status_code == 200


def test_status_reflects_storage_readiness(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.runtime_paths["upload_dir"] = tmp_path / "missing-upload-dir"
        response = client.get("/api/v1/status")

    payload = response.json()
    assert response.status_code == 200
    assert payload["status"] == "degraded"
    assert payload["storage"] == "error"
    assert payload["request_id"]


def test_status_reflects_database_readiness(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.persistence_service.is_database_ready = lambda: False
        response = client.get("/api/v1/status")

    payload = response.json()
    assert response.status_code == 200
    assert payload["status"] == "degraded"
    assert payload["database"] == "error"
    assert payload["request_id"]


def test_openapi_includes_operational_endpoints_and_response_models(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/openapi.json")

    payload = response.json()
    assert response.status_code == 200
    assert "/api/v1/health" in payload["paths"]
    assert "/api/v1/status" in payload["paths"]
    assert "/api/v1/providers" in payload["paths"]

    schemas = payload["components"]["schemas"]
    assert "HealthResponse" in schemas
    assert "StatusResponse" in schemas
    assert "ProvidersResponse" in schemas
