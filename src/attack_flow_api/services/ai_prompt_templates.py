import json
from dataclasses import dataclass
from typing import Any

from attack_flow_api.services.afb_extraction_contracts import AfbExtractionResult
from attack_flow_api.services.ai_orchestration_planner import OrchestrationMode, ProviderOrchestrationInput


ATTACK_VERSION = "19.1"


@dataclass(frozen=True, slots=True)
class PromptTemplateBundle:
    mode: OrchestrationMode
    system_instruction: str
    user_prompt: str
    output_schema: dict[str, Any]


EMPTY_EXTRACTION_REPROMPT_PREFIX = (
    "The previous extraction returned no attack_actions, but this source likely contains attacker behavior that should be captured. "
    "Re-read the full normalized text and extract every clearly supported attack action, even if the ATT&CK mapping is coarse or uncertain. "
    "Do not return an empty attack_actions array when the report describes execution, persistence, credential access, reconnaissance, lateral movement, C2, or other attacker activity.\n\n"
)


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


def build_empty_extraction_reprompt_bundle(
    packaged_input: ProviderOrchestrationInput,
    *,
    source_cues: list[str] | None = None,
) -> PromptTemplateBundle:
    base_bundle = build_prompt_template_bundle(packaged_input)
    cue_text = ""
    if source_cues:
        cue_text = "Strong source cues to focus on:\n" + "\n".join(f"- {cue}" for cue in source_cues) + "\n\n"

    return PromptTemplateBundle(
        mode=base_bundle.mode,
        system_instruction=base_bundle.system_instruction,
        user_prompt=EMPTY_EXTRACTION_REPROMPT_PREFIX + cue_text + base_bundle.user_prompt,
        output_schema=base_bundle.output_schema,
    )


def _build_system_instruction() -> str:
    return (
        "You are an extraction engine that returns JSON only.\n"
        "Follow these hard constraints exactly:\n"
        f"1) If the source explicitly references an ATT&CK tactic or technique, always preserve it as an ATT&CK object.\n"
        "2) Treat ATT&CK IDs in source text, exact or legacy ATT&CK technique/tactic names in source text, STIX attack-pattern objects with ATT&CK external references, and ATT&CK external references on related source objects as explicit ATT&CK evidence.\n"
        f"3) Normalize ATT&CK objects to ATT&CK v{ATTACK_VERSION} when possible.\n"
        "4) If an explicit ATT&CK object cannot be fully normalized with high confidence, preserve the best source-grounded identifier or name available instead of omitting it.\n"
        "5) Never let normalization uncertainty suppress or replace an explicit ATT&CK object.\n"
        "6) If you infer a tactic or technique, only do so when no explicit ATT&CK evidence is present.\n"
        "7) Inferred mappings must have lower confidence than explicit mappings and must explain the reasoning in grounded_by.\n"
        "8) Create attack-action steps even when no technique mapping is available.\n"
        "9) attack-action descriptions must be verbatim source excerpts only.\n"
        "10) Do not paraphrase, summarize, or modify cited source text.\n"
        "11) attack-operator values may only be AND or OR.\n"
        "12) attack-condition values may only be true or false.\n"
        "13) Only create conditions/branching when explicitly grounded in source evidence.\n"
        "14) Preserve authors and external references from source metadata.\n"
        "15) Technique confidence must be in [0.0, 1.0].\n"
        "16) Return output that conforms to the provided AFB-compatible extraction schema.\n"
        "17) Do not wrap the result in legacy afb-extraction envelopes using top-level type/version/source/metadata/deterministic_findings fields."
    )


def _build_full_extraction_prompt(packaged_input: ProviderOrchestrationInput) -> str:
    payload = {
        "mode": "full_extraction",
        "source_type": packaged_input.source_type,
        "attack_version": ATTACK_VERSION,
        "normalized_text": packaged_input.normalized_text,
        "metadata": packaged_input.metadata,
        "constraints": _constraints_payload(packaged_input),
        "required_output_behavior": {
            "preserve_explicit_attack_evidence": True,
            "normalize_to_attack_version": ATTACK_VERSION,
            "preserve_unresolved_explicit_mappings": True,
            "allow_inference_only_when_no_explicit_evidence_exists": True,
            "allow_actions_without_techniques": True,
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
        "attack_version": ATTACK_VERSION,
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
            "preserve_explicit_attack_evidence": True,
            "normalize_to_attack_version": ATTACK_VERSION,
            "preserve_unresolved_explicit_mappings": True,
            "allow_inference_only_when_no_explicit_evidence_exists": True,
            "allow_actions_without_techniques": True,
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
        "no_missing_technique_inference": False,
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
