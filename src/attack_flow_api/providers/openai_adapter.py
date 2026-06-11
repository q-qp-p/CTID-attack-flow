import json
import logging
import os
import time
from dataclasses import dataclass
from http.client import HTTPSConnection
from typing import Callable
from urllib.parse import urlsplit

from attack_flow_api.config import ProviderConfig
from attack_flow_api.providers.adapter import ProviderAdapter, ProviderAdapterInvocationError
from attack_flow_api.providers.contracts import (
    NormalizedProviderError,
    ProviderErrorCategory,
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

@dataclass(frozen=True, slots=True)
class OpenAIHttpRequest:
    method: str
    url: str
    headers: dict[str, str]
    json_body: dict[str, object] | None = None
    timeout_seconds: float = 30.0


@dataclass(frozen=True, slots=True)
class OpenAIHttpResponse:
    status_code: int
    json_body: dict[str, object]


@dataclass(frozen=True, slots=True)
class OpenAIHttpError(RuntimeError):
    status_code: int
    response_body: str | None = None
    response_headers: dict[str, str] | None = None


class OpenAIProviderAdapter(ProviderAdapter):
    def __init__(
        self,
        provider_config: ProviderConfig,
        *,
        request_executor: Callable[[OpenAIHttpRequest], OpenAIHttpResponse] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ):
        self._provider = provider_config
        self._request_executor = request_executor or _default_openai_request_executor
        self._sleep_fn = sleep_fn or time.sleep
        self._logger = logging.getLogger("attack_flow_api.provider_openai")

    @property
    def provider_id(self) -> str:
        return self._provider.provider_id

    @property
    def provider_type(self) -> str:
        return self._provider.provider_type

    def validate(self, request: ProviderValidationRequest) -> ProviderValidationResult:
        api_key = self._resolve_api_key(operation=ProviderOperation.VALIDATE)
        model = self._resolve_model(request.model)
        self._execute_with_retry(
            operation=ProviderOperation.VALIDATE,
            action=lambda: self._request_executor(
                self._build_openai_request(
                    api_key=api_key,
                    timeout_seconds=self._resolve_timeout_seconds(request.timeout_seconds),
                    method="POST",
                    url=self._responses_url(),
                    json_body={
                        "model": model,
                        "input": "ping",
                        "max_output_tokens": 16,
                    },
                )
            ),
            model=model,
        )
        return ProviderValidationResult(
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            is_valid=True,
            checked_model=model,
        )

    def generate_structured(self, request: StructuredGenerationRequest) -> StructuredGenerationResult:
        api_key = self._resolve_api_key(operation=ProviderOperation.STRUCTURED_GENERATION)
        model = self._resolve_model(request.model)

        response = self._execute_with_retry(
            operation=ProviderOperation.STRUCTURED_GENERATION,
            action=lambda: self._request_executor(
                self._build_openai_request(
                    api_key=api_key,
                    timeout_seconds=self._resolve_timeout_seconds(request.timeout_seconds),
                    method="POST",
                    url=self._responses_url(),
                    json_body={
                        "model": model,
                        "input": request.prompt,
                        "temperature": request.temperature,
                        "max_output_tokens": request.max_output_tokens,
                    },
                )
            ),
            model=model,
        )

        usage = _extract_usage(response.json_body)
        output_text = _extract_output_text(response.json_body)
        output_json = _extract_output_json(output_text, request.response_format)

        return StructuredGenerationResult(
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            model=model,
            finish_reason=StructuredFinishReason.UNKNOWN,
            output_text=output_text,
            output_json=output_json,
            usage=usage,
        )

    def list_model_ids(self) -> list[str]:
        api_key = self._resolve_api_key(operation=ProviderOperation.VALIDATE)
        response = self._execute_with_retry(
            operation=ProviderOperation.VALIDATE,
            action=lambda: self._request_executor(
                self._build_openai_request(
                    api_key=api_key,
                    timeout_seconds=self._resolve_timeout_seconds(10.0),
                    method="GET",
                    url=self._models_url(),
                    json_body=None,
                )
            ),
            model=self._provider.default_model or "",
        )

        data = response.json_body.get("data")
        if not isinstance(data, list):
            return []

        model_ids: list[str] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            model_id = item.get("id")
            if isinstance(model_id, str) and model_id.strip():
                model_ids.append(model_id.strip())
        return sorted(dict.fromkeys(model_ids))

    def _resolve_api_key(self, *, operation: ProviderOperation) -> str:
        env_var = (self._provider.api_key_env or "").strip()
        if not env_var:
            raise ProviderAdapterInvocationError(
                build_normalized_provider_error(
                    category=ProviderErrorCategory.CONFIGURATION_ERROR,
                    code="provider_api_key_env_missing",
                    message="provider api key environment variable is not configured",
                    operation=operation,
                    provider_id=self.provider_id,
                    provider_type=self.provider_type,
                )
            )
        api_key = os.environ.get(env_var)
        if api_key is None or not api_key.strip():
            raise ProviderAdapterInvocationError(
                build_normalized_provider_error(
                    category=ProviderErrorCategory.AUTH_FAILURE,
                    code="provider_api_key_missing",
                    message="provider api key is missing",
                    operation=operation,
                    provider_id=self.provider_id,
                    provider_type=self.provider_type,
                    details={"api_key_env": env_var},
                )
            )
        return api_key

    def _build_openai_request(
        self,
        *,
        api_key: str,
        timeout_seconds: float,
        method: str,
        url: str,
        json_body: dict[str, object] | None,
    ) -> OpenAIHttpRequest:
        return OpenAIHttpRequest(
            method=method,
            url=url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout_seconds=timeout_seconds,
            json_body=json_body,
        )

    def _resolve_model(self, requested_model: str | None) -> str:
        if requested_model is not None and requested_model.strip():
            selected = requested_model.strip()
            if self._provider.allowed_models and selected not in self._provider.allowed_models:
                raise ProviderAdapterInvocationError(
                    build_normalized_provider_error(
                        category=ProviderErrorCategory.CONFIGURATION_ERROR,
                        code="provider_model_not_allowed",
                        message="requested provider model is not allowed",
                        operation=ProviderOperation.STRUCTURED_GENERATION,
                        provider_id=self.provider_id,
                        provider_type=self.provider_type,
                        model=selected,
                    )
                )
            return selected
        if self._provider.default_model is not None and self._provider.default_model.strip():
            return self._provider.default_model.strip()
        if self._provider.allowed_models:
            return self._provider.allowed_models[0]
        raise ProviderAdapterInvocationError(
            build_normalized_provider_error(
                category=ProviderErrorCategory.CONFIGURATION_ERROR,
                code="provider_model_missing",
                message="provider model is not configured",
                operation=ProviderOperation.STRUCTURED_GENERATION,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
            )
        )

    def _resolve_timeout_seconds(self, request_timeout_seconds: float) -> float:
        provider_timeout = self._provider.timeout_seconds
        if provider_timeout is None:
            return request_timeout_seconds
        return min(request_timeout_seconds, provider_timeout)

    def _responses_url(self) -> str:
        base_url = (self._provider.base_url or "https://api.openai.com/v1").rstrip("/")
        return f"{base_url}/responses"

    def _models_url(self) -> str:
        base_url = (self._provider.base_url or "https://api.openai.com/v1").rstrip("/")
        return f"{base_url}/models"

    def _execute_with_retry(
        self,
        *,
        operation: ProviderOperation,
        action: Callable[[], OpenAIHttpResponse],
        model: str,
    ) -> OpenAIHttpResponse:
        max_attempts = self._provider.retry_max_attempts or 1
        base_delay_ms = self._provider.retry_base_delay_ms or 200
        max_delay_ms = self._provider.retry_max_delay_ms or 2000

        last_error: NormalizedProviderError | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                return action()
            except ProviderAdapterInvocationError as exc:
                last_error = exc.error
            except Exception as exc:  # pragma: no cover - mapped below
                last_error = self._map_exception_to_normalized_error(
                    exc,
                    operation=operation,
                    model=model,
                )

            if last_error is None:
                continue
            is_last_attempt = attempt >= max_attempts
            if is_last_attempt or not last_error.retryable:
                raise ProviderAdapterInvocationError(last_error)

            delay_seconds = min(base_delay_ms * (2 ** (attempt - 1)), max_delay_ms) / 1000.0
            self._sleep_fn(delay_seconds)

        raise ProviderAdapterInvocationError(
            last_error
            or build_normalized_provider_error(
                category=ProviderErrorCategory.UNAVAILABLE,
                code="provider_request_failed",
                message="provider request failed",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
            )
        )

    def _map_exception_to_normalized_error(
        self,
        exc: Exception,
        *,
        operation: ProviderOperation,
        model: str,
    ) -> NormalizedProviderError:
        if isinstance(exc, TimeoutError):
            return build_normalized_provider_error(
                category=ProviderErrorCategory.TIMEOUT,
                code="provider_timeout",
                message="provider request timed out",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
            )

        if isinstance(exc, OpenAIHttpError):
            status_code = exc.status_code
            response_headers = exc.response_headers or {}
            if status_code == 429:
                self._logger.warning(
                    "openai rate limited status_code=%s request_id=%s retry_after=%s ratelimit_limit=%s ratelimit_remaining=%s ratelimit_reset=%s body_excerpt=%s",
                    status_code,
                    response_headers.get("x-request-id"),
                    response_headers.get("retry-after"),
                    response_headers.get("x-ratelimit-limit-requests")
                    or response_headers.get("x-ratelimit-limit-tokens"),
                    response_headers.get("x-ratelimit-remaining-requests")
                    or response_headers.get("x-ratelimit-remaining-tokens"),
                    response_headers.get("x-ratelimit-reset-requests")
                    or response_headers.get("x-ratelimit-reset-tokens"),
                    _truncate_for_log(exc.response_body),
                )
            if status_code in {401, 403}:
                category = ProviderErrorCategory.AUTH_FAILURE
                code = "provider_auth_failed"
                message = "provider authentication failed"
            elif status_code == 429:
                error_type = _extract_openai_error_type(exc.response_body)
                if error_type == "insufficient_quota":
                    category = ProviderErrorCategory.CONFIGURATION_ERROR
                    code = "provider_quota_exceeded"
                    message = "provider quota exceeded"
                else:
                    category = ProviderErrorCategory.RATE_LIMIT
                    code = "provider_rate_limited"
                    message = "provider rate limit exceeded"
            elif status_code in {408} or 500 <= status_code <= 599:
                category = (
                    ProviderErrorCategory.TIMEOUT if status_code == 408 else ProviderErrorCategory.UNAVAILABLE
                )
                code = "provider_timeout" if status_code == 408 else "provider_unavailable"
                message = "provider request timed out" if status_code == 408 else "provider unavailable"
            elif status_code in {400, 404, 422}:
                category = ProviderErrorCategory.CONFIGURATION_ERROR
                code = "provider_request_invalid"
                message = "provider request configuration is invalid"
            else:
                category = ProviderErrorCategory.INVALID_RESPONSE
                code = "provider_invalid_response"
                message = "provider returned an invalid response"

            return build_normalized_provider_error(
                category=category,
                code=code,
                message=message,
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
                status_code=status_code,
                details=_provider_error_details(response_headers),
            )

        if isinstance(exc, (OSError, ConnectionError)):
            return build_normalized_provider_error(
                category=ProviderErrorCategory.UNAVAILABLE,
                code="provider_network_error",
                message="provider network request failed",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
            )

        if isinstance(exc, (ValueError, json.JSONDecodeError)):
            return build_normalized_provider_error(
                category=ProviderErrorCategory.INVALID_RESPONSE,
                code="provider_invalid_response",
                message="provider returned an invalid response",
                operation=operation,
                provider_id=self.provider_id,
                provider_type=self.provider_type,
                model=model,
            )

        return build_normalized_provider_error(
            category=ProviderErrorCategory.UNAVAILABLE,
            code="provider_request_failed",
            message="provider request failed",
            operation=operation,
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            model=model,
        )


def _default_openai_request_executor(request: OpenAIHttpRequest) -> OpenAIHttpResponse:
    parsed = urlsplit(request.url)
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("openai request url must be https with hostname")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    body = b""
    if request.json_body is not None:
        body = json.dumps(request.json_body).encode("utf-8")

    connection = HTTPSConnection(host=parsed.hostname, port=parsed.port, timeout=request.timeout_seconds)
    try:
        connection.request(request.method, path, body=body, headers=request.headers)
        response = connection.getresponse()
        payload_bytes = response.read()
        payload_text = payload_bytes.decode("utf-8", errors="replace") if payload_bytes else "{}"

        if response.status >= 400:
            raise OpenAIHttpError(
                status_code=response.status,
                response_body=payload_text,
                response_headers=_normalize_headers(response.getheaders()),
            )

        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid json response from provider") from exc
        if not isinstance(payload, dict):
            raise ValueError("provider response payload must be an object")
        return OpenAIHttpResponse(status_code=response.status, json_body=payload)
    except TimeoutError:
        raise
    except OSError:
        raise
    finally:
        connection.close()


def _extract_usage(payload: dict[str, object]) -> ProviderTokenUsage:
    usage_raw = payload.get("usage")
    if not isinstance(usage_raw, dict):
        return ProviderTokenUsage()
    input_tokens = usage_raw.get("input_tokens")
    output_tokens = usage_raw.get("output_tokens")
    total_tokens = usage_raw.get("total_tokens")
    return ProviderTokenUsage(
        input_tokens=input_tokens if isinstance(input_tokens, int) and input_tokens >= 0 else None,
        output_tokens=output_tokens if isinstance(output_tokens, int) and output_tokens >= 0 else None,
        total_tokens=total_tokens if isinstance(total_tokens, int) and total_tokens >= 0 else None,
    )


def _extract_output_text(payload: dict[str, object]) -> str | None:
    output_text = payload.get("output_text")
    if isinstance(output_text, str):
        return output_text
    return None


def _extract_output_json(
    output_text: str | None,
    response_format: StructuredResponseFormat,
) -> dict[str, object] | None:
    if response_format != StructuredResponseFormat.JSON_OBJECT:
        return None
    if output_text is None:
        return None
    try:
        parsed = json.loads(output_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def _normalize_headers(headers: list[tuple[str, str]]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers}


def _provider_error_details(headers: dict[str, str]) -> dict[str, str]:
    details: dict[str, str] = {}
    for key in (
        "x-request-id",
        "retry-after",
        "x-ratelimit-limit-requests",
        "x-ratelimit-remaining-requests",
        "x-ratelimit-reset-requests",
        "x-ratelimit-limit-tokens",
        "x-ratelimit-remaining-tokens",
        "x-ratelimit-reset-tokens",
    ):
        value = headers.get(key)
        if isinstance(value, str) and value.strip():
            details[key] = value.strip()
    return details


def _truncate_for_log(value: str | None, limit: int = 500) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def _extract_openai_error_type(response_body: str | None) -> str | None:
    if response_body is None:
        return None
    try:
        parsed = json.loads(response_body)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    error = parsed.get("error")
    if not isinstance(error, dict):
        return None
    error_type = error.get("type")
    return error_type if isinstance(error_type, str) and error_type.strip() else None
