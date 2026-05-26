import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    ExtractionValidationState,
    OrchestrationMode,
    SourceClassification,
)
from attack_flow_api.services.ai_orchestration_planner import ProviderOrchestrationInput
from attack_flow_api.services.ai_provider_invocation_service import ProviderInvocationResult


@dataclass(frozen=True, slots=True)
class ExtractionOutputValidationResult:
    valid: bool
    extraction_result: AfbExtractionResult | None
    repair_attempted: bool
    error_code: str | None = None
    error_message: str | None = None


def parse_validate_and_repair_extraction_output(
    *,
    invocation_result: ProviderInvocationResult,
    packaged_input: ProviderOrchestrationInput,
) -> ExtractionOutputValidationResult:
    if invocation_result.error_code:
        return ExtractionOutputValidationResult(
            valid=False,
            extraction_result=None,
            repair_attempted=False,
            error_code=invocation_result.error_code,
            error_message=invocation_result.error_message,
        )

    if not invocation_result.provider_invoked and invocation_result.output_json is None and invocation_result.output_text is None:
        fallback = _build_deterministic_only_result(packaged_input)
        return ExtractionOutputValidationResult(
            valid=True,
            extraction_result=fallback,
            repair_attempted=False,
        )

    candidate = invocation_result.output_json
    repair_attempted = False

    if candidate is None:
        parsed = _try_parse_json(invocation_result.output_text)
        if parsed is None:
            repair_attempted = True
            repaired_text = _attempt_single_repair(invocation_result.output_text)
            parsed = _try_parse_json(repaired_text)
        candidate = parsed

    if not isinstance(candidate, dict):
        return ExtractionOutputValidationResult(
            valid=False,
            extraction_result=None,
            repair_attempted=repair_attempted,
            error_code="extraction_output_malformed",
            error_message="provider output is not valid JSON object",
        )

    merged = _merge_deterministic_findings(candidate, packaged_input)
    if repair_attempted:
        merged["repair_attempted"] = True
        if merged.get("validation_state") == "valid":
            merged["validation_state"] = "repaired"

    try:
        extracted = AfbExtractionResult.model_validate(merged)
    except ValidationError as exc:
        return ExtractionOutputValidationResult(
            valid=False,
            extraction_result=None,
            repair_attempted=repair_attempted,
            error_code="extraction_output_schema_invalid",
            error_message=str(exc),
        )

    hard_constraint_error = _validate_hard_constraints(extracted)
    if hard_constraint_error is not None:
        return ExtractionOutputValidationResult(
            valid=False,
            extraction_result=None,
            repair_attempted=repair_attempted,
            error_code=hard_constraint_error,
            error_message="extraction output violates hard constraints",
        )

    return ExtractionOutputValidationResult(
        valid=True,
        extraction_result=extracted,
        repair_attempted=repair_attempted,
    )


def _merge_deterministic_findings(
    candidate: dict[str, Any],
    packaged_input: ProviderOrchestrationInput,
) -> dict[str, Any]:
    merged = dict(candidate)
    merged["deterministic_attack_refs"] = [
        _normalize_deterministic_attack_ref(item) for item in packaged_input.deterministic_attack_refs
    ]
    merged["deterministic_entities"] = list(packaged_input.deterministic_entities)
    merged["deterministic_relationships"] = list(packaged_input.deterministic_relationships)
    merged = _preserve_authors_and_external_references(merged, packaged_input)
    merged = _tag_ai_generated_additions(merged)
    merged = _filter_explicit_object_relationship_attachments(merged)
    return merged


def _normalize_deterministic_attack_ref(item: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(item)
    normalized.setdefault("confidence", 1.0)
    normalized["fact_origin"] = "deterministic_source"
    return normalized


def _preserve_authors_and_external_references(
    merged: dict[str, Any],
    packaged_input: ProviderOrchestrationInput,
) -> dict[str, Any]:
    flow = merged.get("attack_flow")
    if not isinstance(flow, dict):
        return merged

    metadata = packaged_input.metadata
    authors = _as_str_list(metadata.get("authors"))
    external_references = _as_str_list(metadata.get("external_references"))

    flow_authors = _as_str_list(flow.get("authors"))
    flow_refs = _as_str_list(flow.get("external_references"))
    flow["authors"] = _dedupe_preserve_order(flow_authors + authors)
    flow["external_references"] = _dedupe_preserve_order(flow_refs + external_references)
    merged["attack_flow"] = flow
    return merged


def _tag_ai_generated_additions(merged: dict[str, Any]) -> dict[str, Any]:
    for key in ("attack_actions", "attack_conditions", "attack_operators", "attack_assets"):
        values = merged.get(key)
        if not isinstance(values, list):
            continue
        tagged: list[dict[str, Any]] = []
        for item in values:
            if not isinstance(item, dict):
                continue
            out = dict(item)
            out.setdefault("fact_origin", "ai_generated")
            tagged.append(out)
        merged[key] = tagged
    return merged


def _filter_explicit_object_relationship_attachments(merged: dict[str, Any]) -> dict[str, Any]:
    deterministic_entities = merged.get("deterministic_entities")
    deterministic_relationships = merged.get("deterministic_relationships")

    allowed_refs: set[str] = set()
    if isinstance(deterministic_entities, list):
        for item in deterministic_entities:
            if isinstance(item, dict):
                object_id = item.get("object_id")
                if isinstance(object_id, str) and object_id:
                    allowed_refs.add(object_id)
    if isinstance(deterministic_relationships, list):
        for item in deterministic_relationships:
            if not isinstance(item, dict):
                continue
            for field in ("source_ref", "target_ref"):
                ref = item.get(field)
                if isinstance(ref, str) and ref:
                    allowed_refs.add(ref)

    actions = merged.get("attack_actions")
    if isinstance(actions, list):
        filtered_actions: list[dict[str, Any]] = []
        for action in actions:
            if not isinstance(action, dict):
                continue
            out = dict(action)
            object_refs = _as_str_list(out.get("object_refs"))
            if object_refs:
                out["object_refs"] = [ref for ref in object_refs if ref in allowed_refs]
            filtered_actions.append(out)
        merged["attack_actions"] = filtered_actions

    assets = merged.get("attack_assets")
    if isinstance(assets, list):
        filtered_assets: list[dict[str, Any]] = []
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            out = dict(asset)
            object_ref = out.get("object_ref")
            if isinstance(object_ref, str) and object_ref and object_ref not in allowed_refs:
                out["object_ref"] = None
            filtered_assets.append(out)
        merged["attack_assets"] = filtered_assets

    return merged


def _try_parse_json(text: str | None) -> dict[str, Any] | None:
    if text is None:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _attempt_single_repair(text: str | None) -> str | None:
    if text is None:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\\s*```$", "", stripped)

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        stripped = stripped[start : end + 1]
    return stripped


def _validate_hard_constraints(extracted: AfbExtractionResult) -> str | None:
    for action in extracted.attack_actions:
        if action.technique is not None and not action.technique.grounded_by.strip():
            return "technique_not_explicitly_grounded"

        if action.description.strip():
            evidence_excerpts = {item.excerpt for item in action.evidence}
            if action.description not in evidence_excerpts:
                return "action_description_not_verbatim_excerpt"

    return None


def _build_deterministic_only_result(packaged_input: ProviderOrchestrationInput) -> AfbExtractionResult:
    source_classification_map = {
        "narrative_text": SourceClassification.NARRATIVE_TEXT,
        "url_extracted_text": SourceClassification.URL_EXTRACTED_TEXT,
        "document_extracted_text": SourceClassification.DOCUMENT_EXTRACTED_TEXT,
        "stix_structured": SourceClassification.STIX_STRUCTURED,
    }
    source_classification = source_classification_map.get(packaged_input.source_type, SourceClassification.MIXED)
    orchestration_mode = (
        OrchestrationMode.AI_ENRICHMENT
        if packaged_input.mode.value == "enrichment"
        else OrchestrationMode.FULL_EXTRACTION
    )

    metadata = packaged_input.metadata
    return AfbExtractionResult.model_validate(
        {
            "validation_state": ExtractionValidationState.VALID,
            "repair_attempted": False,
            "provider_invoked": False,
            "provider_id": None,
            "model": None,
            "attack_flow": {
                "id": "attack-flow--intermediate",
                "name": str(metadata.get("title") or "AFB Intermediate Extraction"),
                "scope": "incident",
                "start_refs": [],
                "orchestration_mode": orchestration_mode,
                "source_classification": source_classification,
                "authors": _as_str_list(metadata.get("authors")),
                "external_references": _as_str_list(metadata.get("external_references")),
                "provenance": packaged_input.provenance,
            },
            "attack_actions": [],
            "attack_conditions": [],
            "attack_operators": [],
            "attack_assets": [],
            "deterministic_attack_refs": [
                _normalize_deterministic_attack_ref(item)
                for item in packaged_input.deterministic_attack_refs
            ],
            "deterministic_entities": list(packaged_input.deterministic_entities),
            "deterministic_relationships": list(packaged_input.deterministic_relationships),
        }
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


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out
