import pytest

from attack_flow_api.config import ProviderConfig, ProvidersConfig
from attack_flow_api.providers.adapter import ProviderAdapter, ProviderAdapterInvocationError
from attack_flow_api.providers.contracts import ProviderInvocationMode
from attack_flow_api.providers.contracts import ProviderValidationRequest
from attack_flow_api.providers.openai_adapter import OpenAIProviderAdapter
from attack_flow_api.providers.registry import (
    ProviderDisabledError,
    ProviderNotFoundError,
    ProviderRegistry,
)


def _build_providers_config() -> ProvidersConfig:
    return ProvidersConfig(
        providers=[
            ProviderConfig(
                provider_id="default-openai",
                provider_type="openai",
                enabled=True,
                default_model="gpt-4.1-mini",
                allowed_models=["gpt-4.1-mini"],
            ),
            ProviderConfig(
                provider_id="disabled-anthropic",
                provider_type="anthropic",
                enabled=False,
                default_model="claude-3-5-haiku-latest",
            ),
        ]
    )


def test_registry_resolves_enabled_provider_adapter() -> None:
    registry = ProviderRegistry(_build_providers_config())

    adapter = registry.resolve_adapter("default-openai")

    assert isinstance(adapter, ProviderAdapter)
    assert isinstance(adapter, OpenAIProviderAdapter)
    assert adapter.provider_id == "default-openai"
    assert adapter.provider_type == "openai"


def test_registry_raises_for_missing_provider() -> None:
    registry = ProviderRegistry(_build_providers_config())

    with pytest.raises(ProviderNotFoundError) as exc:
        registry.resolve_adapter("missing-provider")

    assert exc.value.provider_id == "missing-provider"


def test_registry_raises_for_disabled_provider() -> None:
    registry = ProviderRegistry(_build_providers_config())

    with pytest.raises(ProviderDisabledError) as exc:
        registry.resolve_adapter("disabled-anthropic")

    assert exc.value.provider_id == "disabled-anthropic"


def test_registry_exposes_safe_public_metadata() -> None:
    registry = ProviderRegistry(_build_providers_config())

    metadata = registry.get_public_metadata("default-openai")

    assert metadata.provider_id == "default-openai"
    assert metadata.provider_type == "openai"
    assert metadata.default_model == "gpt-4.1-mini"
    assert metadata.allowed_models == ["gpt-4.1-mini"]
    assert not hasattr(metadata, "api_key_env")


def test_registry_lists_public_metadata_for_all_configured_providers() -> None:
    registry = ProviderRegistry(_build_providers_config())

    providers = registry.list_public_metadata()

    assert [item.provider_id for item in providers] == ["default-openai", "disabled-anthropic"]


def test_registry_optional_invocation_not_requested() -> None:
    registry = ProviderRegistry(_build_providers_config())

    plan = registry.plan_optional_invocation(
        requested_provider_id=None,
        deterministic_input_sufficient=False,
    )

    assert plan.mode == ProviderInvocationMode.NOT_REQUESTED
    assert plan.adapter is None


def test_registry_optional_invocation_requested_but_skipped() -> None:
    registry = ProviderRegistry(_build_providers_config())

    plan = registry.plan_optional_invocation(
        requested_provider_id="default-openai",
        deterministic_input_sufficient=True,
    )

    assert plan.mode == ProviderInvocationMode.REQUESTED_BUT_SKIPPED_SUFFICIENT_INPUT
    assert plan.provider_id == "default-openai"
    assert plan.provider_type == "openai"
    assert plan.adapter is None


def test_registry_optional_invocation_requested_and_resolved() -> None:
    registry = ProviderRegistry(_build_providers_config())

    plan = registry.plan_optional_invocation(
        requested_provider_id="default-openai",
        deterministic_input_sufficient=False,
    )

    assert plan.mode == ProviderInvocationMode.REQUESTED_AND_RESOLVED
    assert plan.provider_id == "default-openai"
    assert plan.provider_type == "openai"
    assert isinstance(plan.adapter, OpenAIProviderAdapter)


def test_registry_openai_adapter_requires_runtime_credentials() -> None:
    registry = ProviderRegistry(_build_providers_config())
    adapter = registry.resolve_adapter("default-openai")

    with pytest.raises(ProviderAdapterInvocationError):
        adapter.validate(
            ProviderValidationRequest(
                provider_id="default-openai",
                provider_type="openai",
            )
        )
