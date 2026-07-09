from pathlib import Path

from fastapi.testclient import TestClient

from attack_flow_api.main import create_app
from attack_flow_api.services.provider_validation_service import ProviderValidationServiceResult


def _build_client(monkeypatch, tmp_path: Path, *, enabled: bool = True) -> TestClient:
    data_dir = tmp_path / "data"
    providers_path = tmp_path / "providers.yml"
    providers_path.write_text(
        (
            """
providers:
  - provider_id: default-openai
    provider_type: openai
    enabled: {enabled}
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
    default_model: gpt-4.1-mini
    allowed_models:
      - gpt-4.1-mini
""".strip()
            + "\n"
        ).format(enabled="true" if enabled else "false"),
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


def test_validate_provider_endpoint_returns_normalized_result(monkeypatch, tmp_path: Path):
    def fake_validate(self, provider_id: str, model: str | None = None):
        return ProviderValidationServiceResult(
            valid=True,
            provider_id=provider_id,
            provider_type="openai",
            model=model or "gpt-4.1-mini",
            latency_ms=12,
        )

    monkeypatch.setattr(
        "attack_flow_api.services.provider_validation_service.ProviderValidationService.validate_provider",
        fake_validate,
    )

    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/providers/validate",
            json={"provider_id": "default-openai", "model": "gpt-4.1-mini"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["valid"] is True
    assert payload["provider_id"] == "default-openai"
    assert payload["provider_type"] == "openai"
    assert payload["model"] == "gpt-4.1-mini"
    assert payload["latency_ms"] == 12
    assert payload["request_id"]
    assert "api_key" not in payload
    assert "api_key_env" not in payload
    assert "provider_config" not in payload


def test_validate_provider_endpoint_missing_provider_is_normalized(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/providers/validate",
            json={"provider_id": "missing-provider"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["valid"] is False
    assert payload["provider_id"] == "missing-provider"
    assert payload["error_code"] == "provider_not_found"
    assert payload["error_category"] == "configuration_error"
    assert payload["retryable"] is False
    assert payload["request_id"]


def test_validate_provider_endpoint_disabled_provider_is_normalized(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path, enabled=False) as client:
        response = client.post(
            "/api/v1/providers/validate",
            json={"provider_id": "default-openai"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["valid"] is False
    assert payload["provider_id"] == "default-openai"
    assert payload["error_code"] == "provider_disabled"
    assert payload["error_category"] == "configuration_error"
    assert payload["retryable"] is False
    assert payload["request_id"]


def test_validate_provider_endpoint_exposes_error_details(monkeypatch, tmp_path: Path):
    def fake_validate(self, provider_id: str, model: str | None = None):
        return ProviderValidationServiceResult(
            valid=False,
            provider_id=provider_id,
            provider_type="azure_openai",
            model=None,
            latency_ms=7,
            error_code="provider_network_error",
            error_category="unavailable",
            error_message="provider network request failed",
            retryable=True,
            error_details={"request_method": "POST", "https_proxy_set": "true"},
        )

    monkeypatch.setattr(
        "attack_flow_api.services.provider_validation_service.ProviderValidationService.validate_provider",
        fake_validate,
    )

    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/providers/validate",
            json={"provider_id": "default-openai", "model": "gpt-4.1-mini"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["valid"] is False
    assert payload["error_details"]["request_method"] == "POST"
    assert payload["error_details"]["https_proxy_set"] == "true"


def test_validate_provider_endpoint_includes_request_id_header(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/providers/validate",
            json={"provider_id": "missing-provider"},
            headers={"X-Request-ID": "req-test-123"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["request_id"] == "req-test-123"
    assert response.headers["X-Request-ID"] == "req-test-123"


def test_validate_provider_endpoint_accepts_runtime_override(monkeypatch, tmp_path: Path):
    def fake_validate_runtime_provider(
        self,
        *,
        runtime_override,
        allow_runtime_provider_override: bool,
        allowed_provider_types: set[str],
        allow_extra_headers: bool = False,
    ):
        assert allow_runtime_provider_override is False
        assert "openai_compatible" in allowed_provider_types
        assert allow_extra_headers is False
        assert runtime_override.provider_type == "openai_compatible"
        return ProviderValidationServiceResult(
            valid=True,
            provider_id="runtime-openai_compatible",
            provider_type="openai_compatible",
            model="model-a",
            latency_ms=15,
        )

    monkeypatch.setattr(
        "attack_flow_api.services.provider_validation_service.ProviderValidationService.validate_runtime_provider",
        fake_validate_runtime_provider,
    )

    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/providers/validate",
            json={
                "provider_override": {
                    "provider_type": "openai_compatible",
                    "endpoint": "https://compatible.example/v1",
                    "api_key": "runtime-secret",
                    "model": "model-a",
                }
            },
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["valid"] is True
    assert payload["provider_id"] == "runtime-openai_compatible"
    assert payload["provider_type"] == "openai_compatible"
    assert payload["model"] == "model-a"
    assert payload["latency_ms"] == 15
    assert "runtime-secret" not in str(payload)
    assert "api_key" not in payload


def test_validate_provider_endpoint_rejects_ambiguous_provider_selection(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/providers/validate",
            json={
                "provider_id": "default-openai",
                "provider_override": {
                    "provider_type": "openai",
                    "api_key": "runtime-secret",
                    "model": "gpt-4.1-mini",
                },
            },
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_provider_selection"
    assert "runtime-secret" not in response.text
