import json
from dataclasses import dataclass
from typing import Any

from attack_flow_api.services.afb_extraction_contracts import AfbExtractionResult
from attack_flow_api.services.ai_orchestration_planner import OrchestrationMode, ProviderOrchestrationInput


@dataclass(frozen=True, slots=True)
class PromptTemplateBundle:
    mode: OrchestrationMode
    system_instruction: str
    user_prompt: str
    output_schema: dict[str, Any]


def build_prompt_template_bundle(packaged_input: ProviderOrchestrationInput) -> PromptTemplateBundle:
    if packaged_input.mode == OrchestrationMode.ENRICHMENT:
        user_prompt = _build_enrichment_prompt(packaged_input)
    else:
        user_prompt = _build_full_extraction_prompt(packaged_input)

    return PromptTemplateBundle(
        mode=packaged_input.mode,
        system_instruction=_build_system_instruction(),
        user_prompt=user_prompt,
        output_schema=AfbExtractionResult.model_json_schema(),
    )


def _build_system_instruction() -> str:
    return (
        "You are an extraction engine that returns JSON only.\n"
        "Follow these hard constraints exactly:\n"
        "1) Use ATT&CK techniques only when explicitly grounded in source evidence.\n"
        "2) Never infer missing ATT&CK techniques.\n"
        "3) Create attack-action steps even when no technique mapping is available.\n"
        "4) attack-action descriptions must be verbatim source excerpts only.\n"
        "5) Do not paraphrase, summarize, or modify cited source text.\n"
        "6) attack-operator values may only be AND or OR.\n"
        "7) attack-condition values may only be true or false.\n"
        "8) Only create conditions/branching when explicitly grounded in source evidence.\n"
        "9) Preserve authors and external references from source metadata.\n"
        "10) Technique confidence must be in [0.0, 1.0].\n"
        "11) Return output that conforms to the provided AFB-compatible extraction schema."
    )


def _build_full_extraction_prompt(packaged_input: ProviderOrchestrationInput) -> str:
    payload = {
        "mode": "full_extraction",
        "source_type": packaged_input.source_type,
        "normalized_text": packaged_input.normalized_text,
        "metadata": packaged_input.metadata,
        "constraints": _constraints_payload(packaged_input),
        "required_output_behavior": {
            "allow_actions_without_techniques": True,
            "techniques_must_be_explicitly_grounded": True,
            "description_must_be_verbatim": True,
            "preserve_authors": True,
            "preserve_external_references": True,
        },
    }
    return _render_user_prompt(payload)


def _build_enrichment_prompt(packaged_input: ProviderOrchestrationInput) -> str:
    payload = {
        "mode": "enrichment",
        "source_type": packaged_input.source_type,
        "normalized_text": packaged_input.normalized_text,
        "metadata": packaged_input.metadata,
        "structured_summary": packaged_input.structured_summary,
        "deterministic_findings": {
            "attack_refs": packaged_input.deterministic_attack_refs,
            "entities": packaged_input.deterministic_entities,
            "relationships": packaged_input.deterministic_relationships,
            "provenance": packaged_input.provenance,
        },
        "constraints": _constraints_payload(packaged_input),
        "required_output_behavior": {
            "preserve_deterministic_findings": True,
            "do_not_drop_or_rewrite_deterministic_attack_refs": True,
            "allow_actions_without_techniques": True,
            "techniques_must_be_explicitly_grounded": True,
            "description_must_be_verbatim": True,
            "preserve_authors": True,
            "preserve_external_references": True,
        },
    }
    return _render_user_prompt(payload)


def _constraints_payload(packaged_input: ProviderOrchestrationInput) -> dict[str, Any]:
    constraints = packaged_input.constraints
    return {
        "explicit_attack_refs_only": constraints.explicit_attack_refs_only,
        "no_missing_technique_inference": constraints.no_missing_technique_inference,
        "descriptions_must_be_verbatim_excerpts": constraints.descriptions_must_be_verbatim_excerpts,
        "conditions_must_be_source_grounded": constraints.conditions_must_be_source_grounded,
        "operators_must_be_source_grounded": constraints.operators_must_be_source_grounded,
        "allowed_operator_values": list(constraints.allowed_operator_values),
        "allowed_condition_values": list(constraints.allowed_condition_values),
    }


def _render_user_prompt(payload: dict[str, Any]) -> str:
    return (
        "Build an AFB-compatible extraction JSON output from the following packaged source input. "
        "Output must be valid JSON and conform to the provided schema.\n\n"
        f"PACKAGED_INPUT:\n{json.dumps(payload, indent=2, sort_keys=True)}"
    )
