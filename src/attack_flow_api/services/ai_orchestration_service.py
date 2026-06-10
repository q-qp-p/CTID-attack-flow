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

        job = self.persistence_service.get_job(job_id)
        if job is not None:
            self.persistence_service.record_job_event(
                job=job,
                event_type="provider_invocation_started",
                source_component="orchestration",
                message="provider invocation started",
                details={
                    "requested_provider_id": requested_provider_id,
                    "requested_model": requested_model,
                    "deterministic_input_sufficient": packaged_input.deterministic_input_sufficient,
                },
            )

        invocation_result = self.provider_invocation_service.invoke_if_needed(
            packaged_input=packaged_input,
            prompt_bundle=prompt_bundle,
            requested_provider_id=requested_provider_id,
            requested_model=requested_model,
        )

        job = self.persistence_service.get_job(job_id)
        if job is not None:
            if not invocation_result.provider_invoked:
                self.persistence_service.record_job_event(
                    job=job,
                    event_type="provider_invocation_skipped",
                    source_component="orchestration",
                    message="provider invocation skipped",
                    details={
                        "requested_provider_id": requested_provider_id,
                        "requested_model": requested_model,
                        "deterministic_input_sufficient": invocation_result.deterministic_input_sufficient,
                    },
                )
            self.persistence_service.record_job_event(
                job=job,
                event_type="provider_invocation_completed",
                source_component="orchestration",
                message="provider invocation completed",
                details={
                    "provider_invoked": invocation_result.provider_invoked,
                    "provider_id": invocation_result.provider_id,
                    "model_used": invocation_result.model_used,
                    "deterministic_input_sufficient": invocation_result.deterministic_input_sufficient,
                    "error_code": invocation_result.error_code,
                    "error_category": invocation_result.error_category,
                    "retryable": invocation_result.retryable,
                },
            )

        validated = parse_validate_and_repair_extraction_output(
            invocation_result=invocation_result,
            packaged_input=packaged_input,
        )

        job = self.persistence_service.get_job(job_id)
        if job is not None:
            self.persistence_service.record_job_event(
                job=job,
                event_type="structured_extraction_validated",
                source_component="orchestration",
                message="structured extraction validated",
                details={
                    "valid": validated.valid,
                    "repair_attempted": validated.repair_attempted,
                    "error_code": validated.error_code,
                    "error_message": validated.error_message,
                },
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
