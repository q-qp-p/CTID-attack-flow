import time
from dataclasses import dataclass

from attack_flow_api.providers.contracts import ProviderValidationRequest
from attack_flow_api.providers.adapter import ProviderAdapterInvocationError
from attack_flow_api.providers.registry import ProviderDisabledError, ProviderNotFoundError, ProviderRegistry


@dataclass(frozen=True, slots=True)
class ProviderValidationServiceResult:
    valid: bool
    provider_id: str
    provider_type: str | None
    model: str | None
    latency_ms: int
    error_code: str | None = None
    error_category: str | None = None
    error_message: str | None = None
    retryable: bool | None = None
    status_code: int | None = None


class ProviderValidationService:
    def __init__(self, provider_registry: ProviderRegistry):
        self.provider_registry = provider_registry

    def validate_provider(self, provider_id: str, model: str | None = None) -> ProviderValidationServiceResult:
        started = time.perf_counter()
        provider_type: str | None = None

        try:
            provider_config = self.provider_registry.get_provider_config(provider_id)
            provider_type = provider_config.provider_type
            adapter = self.provider_registry.resolve_adapter(provider_id)
            result = adapter.validate(
                request=self._build_validation_request(
                    provider_id=provider_id,
                    provider_type=provider_type,
                    model=model,
                )
            )
            latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
            return ProviderValidationServiceResult(
                valid=bool(result.is_valid),
                provider_id=result.provider_id,
                provider_type=result.provider_type,
                model=result.checked_model,
                latency_ms=latency_ms,
            )
        except ProviderNotFoundError:
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type,
                started=started,
                error_code="provider_not_found",
                error_category="configuration_error",
                error_message="provider not found",
                retryable=False,
            )
        except ProviderDisabledError:
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type,
                started=started,
                error_code="provider_disabled",
                error_category="configuration_error",
                error_message="provider is disabled",
                retryable=False,
            )
        except ProviderAdapterInvocationError as exc:
            normalized_error = exc.error
            return self._failure(
                provider_id=provider_id,
                provider_type=provider_type or normalized_error.provider_type,
                started=started,
                error_code=normalized_error.code,
                error_category=normalized_error.category.value,
                error_message=normalized_error.message,
                retryable=normalized_error.retryable,
                status_code=normalized_error.status_code,
            )

    def _build_validation_request(self, *, provider_id: str, provider_type: str, model: str | None):
        return ProviderValidationRequest(
            provider_id=provider_id,
            provider_type=provider_type,
            model=model,
        )

    def _failure(
        self,
        *,
        provider_id: str,
        provider_type: str | None,
        started: float,
        error_code: str,
        error_category: str,
        error_message: str,
        retryable: bool,
        status_code: int | None = None,
    ) -> ProviderValidationServiceResult:
        latency_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
        return ProviderValidationServiceResult(
            valid=False,
            provider_id=provider_id,
            provider_type=provider_type,
            model=None,
            latency_ms=latency_ms,
            error_code=error_code,
            error_category=error_category,
            error_message=error_message,
            retryable=retryable,
            status_code=status_code,
        )
