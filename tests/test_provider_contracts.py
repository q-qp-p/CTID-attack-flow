from attack_flow_api.providers.contracts import (
    DEFAULT_ERROR_RETRYABLE,
    NormalizedProviderError,
    ProviderErrorCategory,
    ProviderInvocationMode,
    ProviderOperation,
    ProviderTokenUsage,
    ProviderValidationRequest,
    ProviderValidationResult,
    StructuredFinishReason,
    StructuredGenerationRequest,
    StructuredGenerationResult,
    StructuredResponseFormat,
    build_normalized_provider_error,
)


def test_provider_validation_contract_round_trip() -> None:
    request = ProviderValidationRequest(
        provider_id="default-openai",
        provider_type="openai",
        timeout_seconds=5.0,
        model="gpt-4.1-mini",
        metadata={"ticket": "AFA-30"},
    )
    result = ProviderValidationResult(
        provider_id=request.provider_id,
        provider_type=request.provider_type,
        is_valid=True,
        checked_model=request.model,
        latency_ms=45,
    )

    assert result.is_valid is True
    assert result.checked_model == "gpt-4.1-mini"
    assert result.latency_ms == 45


def test_structured_generation_contract_round_trip() -> None:
    request = StructuredGenerationRequest(
        provider_id="default-openai",
        provider_type="openai",
        model="gpt-4.1-mini",
        prompt="Return a JSON object with key risk_level",
        response_format=StructuredResponseFormat.JSON_OBJECT,
        max_output_tokens=256,
    )

    result = StructuredGenerationResult(
        provider_id=request.provider_id,
        provider_type=request.provider_type,
        model=request.model,
        finish_reason=StructuredFinishReason.STOP,
        output_json={"risk_level": "medium"},
        usage=ProviderTokenUsage(input_tokens=24, output_tokens=11, total_tokens=35),
        latency_ms=120,
    )

    assert result.output_json == {"risk_level": "medium"}
    assert result.usage.total_tokens == 35
    assert result.finish_reason == StructuredFinishReason.STOP


def test_normalized_provider_error_categories_and_defaults() -> None:
    for category, expected_retryable in DEFAULT_ERROR_RETRYABLE.items():
        error = build_normalized_provider_error(
            category=category,
            code=f"code_{category.value}",
            message="failure",
            operation=ProviderOperation.STRUCTURED_GENERATION,
            provider_id="provider-1",
            provider_type="openai",
            model="gpt-4.1-mini",
            status_code=503,
        )
        assert isinstance(error, NormalizedProviderError)
        assert error.category == category
        assert error.retryable is expected_retryable


def test_normalized_provider_error_retryable_override() -> None:
    error = build_normalized_provider_error(
        category=ProviderErrorCategory.CONFIGURATION_ERROR,
        code="temporary_config_error",
        message="temporary",
        operation=ProviderOperation.VALIDATE,
        retryable=True,
    )
    assert error.retryable is True


def test_invocation_mode_values_are_explicit() -> None:
    assert ProviderInvocationMode.NOT_REQUESTED.value == "not_requested"
    assert (
        ProviderInvocationMode.REQUESTED_BUT_SKIPPED_SUFFICIENT_INPUT.value
        == "requested_but_skipped_sufficient_input"
    )
    assert ProviderInvocationMode.REQUESTED_AND_RESOLVED.value == "requested_and_resolved"
