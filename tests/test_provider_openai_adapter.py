import pytest

from attack_flow_api.config import ProviderConfig
from attack_flow_api.providers.adapter import ProviderAdapterInvocationError
from attack_flow_api.providers.contracts import ProviderValidationRequest, StructuredGenerationRequest
from attack_flow_api.providers.openai_adapter import (
    OpenAIHttpError,
    OpenAIHttpResponse,
    OpenAIProviderAdapter,
)


def _provider_config() -> ProviderConfig:
    return ProviderConfig(
        provider_id="default-openai",
        provider_type="openai",
        enabled=True,
        api_key_env="OPENAI_API_KEY",
        default_model="gpt-4.1-mini",
        allowed_models=["gpt-4.1-mini", "gpt-4.1"],
        retry_max_attempts=3,
        retry_base_delay_ms=1,
        retry_max_delay_ms=1,
    )


def test_validate_succeeds_with_injected_executor(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: OpenAIHttpResponse(status_code=200, json_body={"ok": True}),
    )

    result = adapter.validate(
        ProviderValidationRequest(
            provider_id="default-openai",
            provider_type="openai",
        )
    )

    assert result.is_valid is True
    assert result.checked_model == "gpt-4.1-mini"


def test_validate_maps_auth_error(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(OpenAIHttpError(status_code=401)),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(
            ProviderValidationRequest(provider_id="default-openai", provider_type="openai")
        )

    assert exc.value.error.category.value == "auth_failure"
    assert exc.value.error.code == "provider_auth_failed"
    assert exc.value.error.retryable is False


def test_validate_retries_and_maps_rate_limit(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    attempts = {"count": 0}

    def executor(request):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise OpenAIHttpError(status_code=429)
        return OpenAIHttpResponse(status_code=200, json_body={"ok": True})

    sleeps: list[float] = []
    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor, sleep_fn=sleeps.append)

    result = adapter.validate(
        ProviderValidationRequest(provider_id="default-openai", provider_type="openai")
    )

    assert result.is_valid is True
    assert attempts["count"] == 3
    assert sleeps == [0.001, 0.001]


def test_generate_structured_returns_text_and_json(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: OpenAIHttpResponse(
            status_code=200,
            json_body={
                "output_text": '{"risk_level":"high"}',
                "usage": {"input_tokens": 12, "output_tokens": 8, "total_tokens": 20},
            },
        ),
    )

    result = adapter.generate_structured(
        StructuredGenerationRequest(
            provider_id="default-openai",
            provider_type="openai",
            model="gpt-4.1-mini",
            prompt="risk summary",
        )
    )

    assert result.output_text == '{"risk_level":"high"}'
    assert result.output_json == {"risk_level": "high"}
    assert result.usage.total_tokens == 20


def test_generate_structured_maps_timeout(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(TimeoutError("timed out")),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="default-openai",
                provider_type="openai",
                model="gpt-4.1-mini",
                prompt="risk summary",
            )
        )

    assert exc.value.error.category.value == "timeout"
    assert exc.value.error.code == "provider_timeout"
    assert exc.value.error.retryable is True


def test_validate_maps_unavailable_error(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(OpenAIHttpError(status_code=503)),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(
            ProviderValidationRequest(provider_id="default-openai", provider_type="openai")
        )

    assert exc.value.error.category.value == "unavailable"
    assert exc.value.error.code == "provider_unavailable"
    assert exc.value.error.retryable is True


def test_generate_structured_maps_invalid_response_error(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(
        _provider_config(),
        request_executor=lambda request: (_ for _ in ()).throw(ValueError("bad response")),
    )

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="default-openai",
                provider_type="openai",
                model="gpt-4.1-mini",
                prompt="risk summary",
            )
        )

    assert exc.value.error.category.value == "invalid_response"
    assert exc.value.error.code == "provider_invalid_response"
    assert exc.value.error.retryable is False


def test_generate_structured_rejects_disallowed_model_override(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    adapter = OpenAIProviderAdapter(_provider_config())

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.generate_structured(
            StructuredGenerationRequest(
                provider_id="default-openai",
                provider_type="openai",
                model="gpt-5",
                prompt="risk summary",
            )
        )

    assert exc.value.error.code == "provider_model_not_allowed"
    assert exc.value.error.category.value == "configuration_error"


def test_validate_uses_provider_default_model_when_request_model_missing(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    seen = {"model": None}

    def executor(request):
        assert request.json_body is not None
        seen["model"] = request.json_body.get("model")
        return OpenAIHttpResponse(status_code=200, json_body={"ok": True})

    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor)
    result = adapter.validate(
        ProviderValidationRequest(
            provider_id="default-openai",
            provider_type="openai",
        )
    )

    assert result.checked_model == "gpt-4.1-mini"
    assert seen["model"] == "gpt-4.1-mini"


def test_request_timeout_is_capped_by_provider_timeout(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    config = _provider_config()
    config.timeout_seconds = 3
    seen = {"timeout": None}

    def executor(request):
        seen["timeout"] = request.timeout_seconds
        return OpenAIHttpResponse(status_code=200, json_body={"ok": True})

    adapter = OpenAIProviderAdapter(config, request_executor=executor)
    adapter.validate(
        ProviderValidationRequest(
            provider_id="default-openai",
            provider_type="openai",
            timeout_seconds=10,
        )
    )
    assert seen["timeout"] == 3


def test_auth_failure_is_not_retried(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    attempts = {"count": 0}

    def executor(request):
        attempts["count"] += 1
        raise OpenAIHttpError(status_code=401)

    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor)

    with pytest.raises(ProviderAdapterInvocationError):
        adapter.validate(ProviderValidationRequest(provider_id="default-openai", provider_type="openai"))

    assert attempts["count"] == 1


def test_unavailable_failure_retries_until_bounded_limit(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    attempts = {"count": 0}
    sleeps: list[float] = []

    def executor(request):
        attempts["count"] += 1
        raise OpenAIHttpError(status_code=503)

    adapter = OpenAIProviderAdapter(_provider_config(), request_executor=executor, sleep_fn=sleeps.append)

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="default-openai", provider_type="openai"))

    assert exc.value.error.category.value == "unavailable"
    assert attempts["count"] == 3
    assert sleeps == [0.001, 0.001]


def test_missing_api_key_never_leaks_secret(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    adapter = OpenAIProviderAdapter(_provider_config())

    with pytest.raises(ProviderAdapterInvocationError) as exc:
        adapter.validate(ProviderValidationRequest(provider_id="default-openai", provider_type="openai"))

    assert exc.value.error.code == "provider_api_key_missing"
    assert "test-key" not in exc.value.error.message
