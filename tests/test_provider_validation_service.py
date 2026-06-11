from dataclasses import dataclass

from attack_flow_api.config import ProviderConfig, ProvidersConfig
from attack_flow_api.providers.adapter import ProviderAdapter
from attack_flow_api.providers.openai_adapter import OpenAIProviderAdapter
from attack_flow_api.providers.registry import ProviderRegistry
from attack_flow_api.services.provider_validation_service import ProviderValidationService


def _registry_with_openai() -> ProviderRegistry:
    return ProviderRegistry(
        ProvidersConfig(
            providers=[
                ProviderConfig(
                    provider_id="default-openai",
                    provider_type="openai",
                    enabled=True,
                    api_key_env="OPENAI_API_KEY",
                    default_model="gpt-4.1-mini",
                )
            ]
        )
    )


@dataclass(slots=True)
class _FakeRegistry:
    config: ProviderConfig
    adapter: ProviderAdapter

    def get_provider_config(self, provider_id: str) -> ProviderConfig:
        if provider_id != self.config.provider_id:
            from attack_flow_api.providers.registry import ProviderNotFoundError

            raise ProviderNotFoundError(provider_id)
        return self.config

    def resolve_adapter(self, provider_id: str) -> ProviderAdapter:
        if provider_id != self.config.provider_id:
            from attack_flow_api.providers.registry import ProviderNotFoundError

            raise ProviderNotFoundError(provider_id)
        return self.adapter


def test_validate_provider_success(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    provider_config = ProviderConfig(
        provider_id="default-openai",
        provider_type="openai",
        enabled=True,
        api_key_env="OPENAI_API_KEY",
        default_model="gpt-4.1-mini",
    )
    adapter = OpenAIProviderAdapter(
        provider_config,
        request_executor=lambda request: __import__("attack_flow_api.providers.openai_adapter", fromlist=["OpenAIHttpResponse"]).OpenAIHttpResponse(status_code=200, json_body={"ok": True}),
    )

    service = ProviderValidationService(_FakeRegistry(config=provider_config, adapter=adapter))
    result = service.validate_provider("default-openai")

    assert result.valid is True
    assert result.provider_id == "default-openai"
    assert result.provider_type == "openai"
    assert result.model == "gpt-4.1-mini"
    assert result.latency_ms >= 0
    assert result.error_code is None


def test_validate_provider_missing_provider() -> None:
    service = ProviderValidationService(_registry_with_openai())

    result = service.validate_provider("missing")

    assert result.valid is False
    assert result.provider_id == "missing"
    assert result.error_code == "provider_not_found"
    assert result.error_category == "configuration_error"
    assert result.retryable is False


def test_validate_provider_disabled_provider() -> None:
    registry = ProviderRegistry(
        ProvidersConfig(
            providers=[
                ProviderConfig(
                    provider_id="disabled-openai",
                    provider_type="openai",
                    enabled=False,
                    api_key_env="OPENAI_API_KEY",
                    default_model="gpt-4.1-mini",
                )
            ]
        )
    )
    service = ProviderValidationService(registry)

    result = service.validate_provider("disabled-openai")

    assert result.valid is False
    assert result.provider_id == "disabled-openai"
    assert result.error_code == "provider_disabled"
    assert result.error_category == "configuration_error"
    assert result.retryable is False


def test_validate_provider_normalizes_adapter_failures(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider_config = ProviderConfig(
        provider_id="default-openai",
        provider_type="openai",
        enabled=True,
        api_key_env="OPENAI_API_KEY",
        default_model="gpt-4.1-mini",
    )
    adapter = OpenAIProviderAdapter(provider_config)
    service = ProviderValidationService(_FakeRegistry(config=provider_config, adapter=adapter))

    result = service.validate_provider("default-openai")

    assert result.valid is False
    assert result.provider_id == "default-openai"
    assert result.provider_type == "openai"
    assert result.error_code == "provider_api_key_missing"
    assert result.error_category == "auth_failure"
    assert result.error_message
    assert result.retryable is False
