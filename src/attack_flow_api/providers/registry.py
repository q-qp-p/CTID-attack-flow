from dataclasses import dataclass

from attack_flow_api.config import ProviderConfig, ProviderPublicMetadata, ProvidersConfig
from attack_flow_api.providers.adapter import ProviderAdapter, ProviderNotImplementedAdapter
from attack_flow_api.providers.contracts import ProviderInvocationMode


class ProviderRegistryError(RuntimeError):
    pass


class ProviderNotFoundError(ProviderRegistryError):
    def __init__(self, provider_id: str):
        super().__init__(f"provider not found: {provider_id}")
        self.provider_id = provider_id


class ProviderDisabledError(ProviderRegistryError):
    def __init__(self, provider_id: str):
        super().__init__(f"provider is disabled: {provider_id}")
        self.provider_id = provider_id


@dataclass(frozen=True, slots=True)
class _ProviderRegistration:
    config: ProviderConfig
    adapter: ProviderAdapter


@dataclass(frozen=True, slots=True)
class ProviderInvocationPlan:
    mode: ProviderInvocationMode
    provider_id: str | None = None
    provider_type: str | None = None
    adapter: ProviderAdapter | None = None

    @classmethod
    def not_requested(cls) -> "ProviderInvocationPlan":
        return cls(mode=ProviderInvocationMode.NOT_REQUESTED)

    @classmethod
    def requested_but_skipped(
        cls,
        *,
        provider_id: str,
        provider_type: str,
    ) -> "ProviderInvocationPlan":
        return cls(
            mode=ProviderInvocationMode.REQUESTED_BUT_SKIPPED_SUFFICIENT_INPUT,
            provider_id=provider_id,
            provider_type=provider_type,
            adapter=None,
        )

    @classmethod
    def requested_and_resolved(
        cls,
        *,
        provider_id: str,
        provider_type: str,
        adapter: ProviderAdapter,
    ) -> "ProviderInvocationPlan":
        return cls(
            mode=ProviderInvocationMode.REQUESTED_AND_RESOLVED,
            provider_id=provider_id,
            provider_type=provider_type,
            adapter=adapter,
        )


class ProviderRegistry:
    def __init__(self, providers_config: ProvidersConfig):
        self._providers_config = providers_config
        self._registrations: dict[str, _ProviderRegistration] = {}
        for provider in providers_config.providers:
            self._registrations[provider.provider_id] = _ProviderRegistration(
                config=provider,
                adapter=self._build_adapter(provider),
            )

    def list_public_metadata(self) -> list[ProviderPublicMetadata]:
        return self._providers_config.list_public_metadata()

    def get_public_metadata(self, provider_id: str) -> ProviderPublicMetadata:
        registration = self._require_registration(provider_id)
        return registration.config.to_public_metadata()

    def get_provider_config(self, provider_id: str) -> ProviderConfig:
        registration = self._require_registration(provider_id)
        return registration.config

    def resolve_adapter(self, provider_id: str) -> ProviderAdapter:
        return self._require_enabled_registration(provider_id).adapter

    def plan_optional_invocation(
        self,
        *,
        requested_provider_id: str | None,
        deterministic_input_sufficient: bool,
    ) -> ProviderInvocationPlan:
        if requested_provider_id is None or not requested_provider_id.strip():
            return ProviderInvocationPlan.not_requested()

        registration = self._require_enabled_registration(requested_provider_id)

        if deterministic_input_sufficient:
            return ProviderInvocationPlan.requested_but_skipped(
                provider_id=registration.config.provider_id,
                provider_type=registration.config.provider_type,
            )

        return ProviderInvocationPlan.requested_and_resolved(
            provider_id=registration.config.provider_id,
            provider_type=registration.config.provider_type,
            adapter=registration.adapter,
        )

    def _require_registration(self, provider_id: str) -> _ProviderRegistration:
        normalized = provider_id.strip()
        if not normalized:
            raise ProviderNotFoundError(provider_id)
        registration = self._registrations.get(normalized)
        if registration is None:
            raise ProviderNotFoundError(provider_id)
        return registration

    def _require_enabled_registration(self, provider_id: str) -> _ProviderRegistration:
        registration = self._require_registration(provider_id)
        if not registration.config.enabled:
            raise ProviderDisabledError(registration.config.provider_id)
        return registration

    def _build_adapter(self, provider: ProviderConfig) -> ProviderAdapter:
        return ProviderNotImplementedAdapter(
            provider_id=provider.provider_id,
            provider_type=provider.provider_type,
        )
