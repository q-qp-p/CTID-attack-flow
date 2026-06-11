import json
from dataclasses import dataclass

from attack_flow_api.providers.adapter import ProviderAdapterInvocationError
from attack_flow_api.providers.contracts import StructuredGenerationRequest, StructuredResponseFormat
from attack_flow_api.providers.registry import ProviderRegistry
from attack_flow_api.services.ai_orchestration_planner import ProviderOrchestrationInput
from attack_flow_api.services.ai_prompt_templates import PromptTemplateBundle


@dataclass(frozen=True, slots=True)
class ProviderInvocationResult:
    provider_invoked: bool
    provider_id: str | None
    model_used: str | None
    deterministic_input_sufficient: bool
    output_json: dict[str, object] | None = None
    output_text: str | None = None
    error_code: str | None = None
    error_category: str | None = None
    error_message: str | None = None
    retryable: bool | None = None


class AIProviderInvocationService:
    def __init__(self, provider_registry: ProviderRegistry):
        self.provider_registry = provider_registry

    def invoke_if_needed(
        self,
        *,
        packaged_input: ProviderOrchestrationInput,
        prompt_bundle: PromptTemplateBundle,
        requested_provider_id: str | None,
        requested_model: str | None = None,
    ) -> ProviderInvocationResult:
        plan = self.provider_registry.plan_optional_invocation(
            requested_provider_id=requested_provider_id,
            deterministic_input_sufficient=packaged_input.deterministic_input_sufficient,
        )

        if plan.adapter is None:
            return ProviderInvocationResult(
                provider_invoked=False,
                provider_id=plan.provider_id,
                model_used=None,
                deterministic_input_sufficient=packaged_input.deterministic_input_sufficient,
            )

        selected_model = requested_model
        if selected_model is None:
            provider_config = self.provider_registry.get_provider_config(plan.provider_id or "")
            selected_model = provider_config.default_model or (
                provider_config.allowed_models[0] if provider_config.allowed_models else None
            )

        generation_request = StructuredGenerationRequest(
            provider_id=plan.provider_id or "",
            provider_type=plan.provider_type or "",
            model=selected_model or "",
            prompt=self._compose_provider_prompt(prompt_bundle),
            response_format=StructuredResponseFormat.JSON_OBJECT,
        )

        try:
            response = plan.adapter.generate_structured(generation_request)
            return ProviderInvocationResult(
                provider_invoked=True,
                provider_id=response.provider_id,
                model_used=response.model,
                deterministic_input_sufficient=packaged_input.deterministic_input_sufficient,
                output_json=response.output_json,
                output_text=response.output_text,
            )
        except ProviderAdapterInvocationError as exc:
            normalized_error = exc.error
            return ProviderInvocationResult(
                provider_invoked=True,
                provider_id=plan.provider_id,
                model_used=selected_model,
                deterministic_input_sufficient=packaged_input.deterministic_input_sufficient,
                error_code=normalized_error.code,
                error_category=normalized_error.category.value,
                error_message=normalized_error.message,
                retryable=normalized_error.retryable,
            )

    def _compose_provider_prompt(self, prompt_bundle: PromptTemplateBundle) -> str:
        schema_json = json.dumps(prompt_bundle.output_schema, indent=2, sort_keys=True)
        return (
            f"SYSTEM_INSTRUCTION:\n{prompt_bundle.system_instruction}\n\n"
            f"USER_PROMPT:\n{prompt_bundle.user_prompt}\n\n"
            f"OUTPUT_SCHEMA:\n{schema_json}\n"
        )
