import json
from dataclasses import dataclass

from attack_flow_api.services.ai_orchestration_planner import build_provider_orchestration_input
from attack_flow_api.services.ai_output_validation_service import (
    ExtractionOutputValidationResult,
    parse_validate_and_repair_extraction_output,
)
from attack_flow_api.services.ai_prompt_templates import build_prompt_template_bundle
from attack_flow_api.services.ai_provider_invocation_service import AIProviderInvocationService
from attack_flow_api.services.persistence_service import PersistenceService


@dataclass(frozen=True, slots=True)
class AIOrchestrationExecutionResult:
    succeeded: bool
    provider_invoked: bool
    provider_id: str | None
    model_used: str | None
    extraction_mode: str
    extraction_payload_json: str
    extraction_validation_state: str
    repair_attempted: bool
    provenance_classification: str
    authors_json: str
    external_references_json: str
    error_code: str | None = None
    error_message: str | None = None


class AIOrchestrationService:
    def __init__(
        self,
        *,
        persistence_service: PersistenceService,
        provider_invocation_service: AIProviderInvocationService,
    ):
        self.persistence_service = persistence_service
        self.provider_invocation_service = provider_invocation_service

    def run_for_job(
        self,
        *,
        job_id: str,
        requested_provider_id: str | None,
        requested_model: str | None,
    ) -> AIOrchestrationExecutionResult:
        normalized_package = self.persistence_service.resolve_normalized_package_for_job(job_id)
        if normalized_package is None:
            return AIOrchestrationExecutionResult(
                succeeded=False,
                provider_invoked=False,
                provider_id=requested_provider_id,
                model_used=requested_model,
                extraction_mode="full_extraction",
                extraction_payload_json="{}",
                extraction_validation_state="invalid",
                repair_attempted=False,
                provenance_classification="unknown",
                authors_json="[]",
                external_references_json="[]",
                error_code="normalized_package_missing",
                error_message="canonical normalized package is not available",
            )

        packaged_input = build_provider_orchestration_input(normalized_package)
        prompt_bundle = build_prompt_template_bundle(packaged_input)

        invocation_result = self.provider_invocation_service.invoke_if_needed(
            packaged_input=packaged_input,
            prompt_bundle=prompt_bundle,
            requested_provider_id=requested_provider_id,
            requested_model=requested_model,
        )

        validated = parse_validate_and_repair_extraction_output(
            invocation_result=invocation_result,
            packaged_input=packaged_input,
        )

        return _to_execution_result(
            invocation_result=invocation_result,
            validated=validated,
            packaged_input=packaged_input,
        )


def _to_execution_result(
    *,
    invocation_result,
    validated: ExtractionOutputValidationResult,
    packaged_input,
) -> AIOrchestrationExecutionResult:
    metadata = packaged_input.metadata
    authors = _as_str_list(metadata.get("authors"))
    external_references = _as_str_list(metadata.get("external_references"))

    if not validated.valid or validated.extraction_result is None:
        return AIOrchestrationExecutionResult(
            succeeded=False,
            provider_invoked=invocation_result.provider_invoked,
            provider_id=invocation_result.provider_id,
            model_used=invocation_result.model_used,
            extraction_mode=packaged_input.mode.value,
            extraction_payload_json="{}",
            extraction_validation_state="invalid",
            repair_attempted=validated.repair_attempted,
            provenance_classification=packaged_input.source_type,
            authors_json=_to_json_list(authors),
            external_references_json=_to_json_list(external_references),
            error_code=validated.error_code,
            error_message=validated.error_message,
        )

    return AIOrchestrationExecutionResult(
        succeeded=True,
        provider_invoked=invocation_result.provider_invoked,
        provider_id=invocation_result.provider_id,
        model_used=invocation_result.model_used,
        extraction_mode=packaged_input.mode.value,
        extraction_payload_json=json.dumps(validated.extraction_result.model_dump(mode="json")),
        extraction_validation_state=validated.extraction_result.validation_state.value,
        repair_attempted=validated.extraction_result.repair_attempted,
        provenance_classification=packaged_input.source_type,
        authors_json=_to_json_list(authors),
        external_references_json=_to_json_list(external_references),
    )


def _as_str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if candidate:
            out.append(candidate)
    return out


def _to_json_list(values: list[str]) -> str:
    return json.dumps(values)
