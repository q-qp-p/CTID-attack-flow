import pytest
from pydantic import ValidationError

from attack_flow_api.config import ProviderConfig, ProvidersConfig


def test_provider_config_model_validates_canonical_fields() -> None:
    config = ProviderConfig(
        provider_id="default-openai",
        provider_type="openai",
        enabled=True,
        default_model="gpt-4.1-mini",
        allowed_models=["gpt-4.1-mini", "gpt-4.1"],
        base_url="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
    )

    assert config.provider_id == "default-openai"
    assert config.provider_type == "openai"
    assert config.default_model == "gpt-4.1-mini"
    assert config.allowed_models == ["gpt-4.1-mini", "gpt-4.1"]


def test_provider_config_model_rejects_invalid_provider_type() -> None:
    with pytest.raises(ValidationError):
        ProviderConfig(
            provider_id="bad-provider",
            provider_type="unsupported",  # type: ignore[arg-type]
        )


def test_public_provider_metadata_excludes_secret_fields() -> None:
    config = ProviderConfig(
        provider_id="azure-primary",
        provider_type="azure_openai",
        enabled=True,
        api_key_env="AZURE_OPENAI_KEY",
        azure_api_key_env="AZURE_OPENAI_KEY",
        azure_ad_token_env="AZURE_AD_TOKEN",
        default_model="gpt-4.1-mini",
        allowed_models=["gpt-4.1-mini"],
        base_url="https://example.openai.azure.com",
        api_version="2024-10-21",
    )

    public = config.to_public_metadata()
    payload = public.model_dump()

    assert payload["provider_id"] == "azure-primary"
    assert payload["provider_type"] == "azure_openai"
    assert payload["default_model"] == "gpt-4.1-mini"
    assert payload["allowed_models"] == ["gpt-4.1-mini"]
    assert "api_key_env" not in payload
    assert "azure_api_key_env" not in payload
    assert "azure_ad_token_env" not in payload
    assert "provider_config" not in payload


def test_providers_config_lookup_and_lists() -> None:
    providers = ProvidersConfig(
        providers=[
            ProviderConfig(provider_id="p1", provider_type="openai", enabled=True),
            ProviderConfig(provider_id="p2", provider_type="anthropic", enabled=False),
        ]
    )

    assert providers.get_provider_by_id("p1") is not None
    assert providers.get_provider_by_id("missing") is None
    assert [item.provider_id for item in providers.list_enabled_providers()] == ["p1"]
    assert [item.provider_id for item in providers.list_public_metadata()] == ["p1", "p2"]
