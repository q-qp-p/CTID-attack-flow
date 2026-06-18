from attack_flow_api.services.ai_orchestration_planner import build_provider_orchestration_input
from attack_flow_api.services.ai_prompt_templates import build_empty_extraction_reprompt_bundle, build_prompt_template_bundle


def test_full_extraction_prompt_contains_required_rules() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Observed command: whoami",
            "metadata": {"authors": ["analyst-a"], "external_references": ["https://example.com"]},
        }
    )

    bundle = build_prompt_template_bundle(packaged)

    assert bundle.mode.value == "full_extraction"
    assert "always preserve it as an ATT&CK object" in bundle.system_instruction
    assert "Treat ATT&CK IDs in source text" in bundle.system_instruction
    assert "ATT&CK v19.1" in bundle.system_instruction
    assert "attack-action descriptions must be verbatim source excerpts only; names should be concise summaries" in bundle.system_instruction
    assert "attack-operator values may only be AND or OR, and attack-condition values may only be true or false" in bundle.system_instruction
    assert "Create attack-operator and attack-condition only when the source explicitly expresses branching or sibling-step logic" in bundle.system_instruction
    assert "Prefer no branching over guessed branching; do not invent branching from unrelated text" in bundle.system_instruction
    assert "If the source clearly shows a decision point, emit attack-condition and attack-operator nodes rather than flattening the branch into linear actions" in bundle.system_instruction
    assert "do not invent branching from unrelated text" in bundle.system_instruction
    assert "If you create an attack-condition or attack-operator, keep its description and evidence verbatim and source-grounded" in bundle.system_instruction
    assert "Use the supported STIX catalog as linked deterministic_entities and deterministic_relationships" in bundle.system_instruction
    assert "Asset-like or support objects should usually be linked entities instead of standalone attack_assets" in bundle.system_instruction
    assert "Use object_id and object_type keys in deterministic_entities, not entity_id/entity_type" in bundle.system_instruction
    assert "If the source provides evidence for a supported field, populate it" in bundle.system_instruction
    assert "When you emit attack_assets, include a concise name, a source-grounded description when available, and tags" in bundle.system_instruction
    assert "When you emit ATT&CK technique support data on attack_actions" in bundle.system_instruction
    assert "Only procedural attacker steps should become attack-action nodes" in bundle.system_instruction
    assert "single top-level JSON object with the AFB extraction fields validation_state, provider_invoked, attack_flow" in bundle.system_instruction
    assert "legacy fields like type, id, spec_version, objects, technique_refs, or deterministic_entity_refs" in bundle.system_instruction
    assert "PACKAGED_INPUT" in bundle.user_prompt
    assert '"mode": "full_extraction"' in bundle.user_prompt
    assert '"attack_version": "19.1"' in bundle.user_prompt
    assert '"structured_summary": {}' in bundle.user_prompt
    assert '"stix_context": {' in bundle.user_prompt
    assert '"ui_supported_object_types": [' in bundle.user_prompt
    assert '"tool"' in bundle.user_prompt
    assert '"ui_supported_observable_types": [' in bundle.user_prompt
    assert '"ipv4_addr"' in bundle.user_prompt
    assert '"windows_registry_key"' in bundle.user_prompt
    assert '"preserve_explicit_attack_evidence": true' in bundle.user_prompt
    assert '"normalize_to_attack_version": "19.1"' in bundle.user_prompt
    assert '"preserve_explicit_stix_objects": true' in bundle.user_prompt
    assert '"preserve_explicit_stix_relationships": true' in bundle.user_prompt
    assert '"preserve_explicit_branching_logic": true' in bundle.user_prompt
    assert '"allow_inferred_branching_when_supported": true' in bundle.user_prompt
    assert '"emit_attack_conditions_for_decisions": true' in bundle.user_prompt
    assert '"use_and_operator_for_multi_step_sets": true' in bundle.user_prompt
    assert '"prefer_linked_objects_over_actions": true' in bundle.user_prompt
    assert '"prefer_attached_stix_catalog_objects": true' in bundle.user_prompt
    assert '"output_shape_reminder": {' in bundle.user_prompt
    assert '"top_level_fields": [' in bundle.user_prompt
    assert '"attack_action_technique_field": "attack_actions[*].technique"' in bundle.user_prompt
    assert '"legacy_fields_forbidden": [' in bundle.user_prompt
    assert '"objects"' in bundle.user_prompt


def test_enrichment_prompt_preserves_deterministic_findings() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "stix_structured",
            "normalized_text": "Narrative from report",
            "structured_summary": {"bundle_metadata": {"id": "bundle--1"}},
            "attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--1"}],
            "entities": [{"object_id": "malware--1", "object_type": "malware"}],
            "relationships": [
                {
                    "relationship_id": "relationship--1",
                    "relationship_type": "uses",
                    "source_ref": "threat-actor--1",
                    "target_ref": "malware--1",
                }
            ],
            "provenance": {"narrative_source_object_ids": ["report--1"]},
        }
    )

    bundle = build_prompt_template_bundle(packaged)

    assert bundle.mode.value == "enrichment"
    assert '"mode": "enrichment"' in bundle.user_prompt
    assert '"deterministic_findings"' in bundle.user_prompt
    assert '"ui_supported_object_types": [' in bundle.user_prompt
    assert '"ui_supported_observable_types": [' in bundle.user_prompt
    assert '"preserve_explicit_stix_objects": true' in bundle.user_prompt
    assert '"preserve_explicit_stix_relationships": true' in bundle.user_prompt
    assert '"preserve_deterministic_findings": true' in bundle.user_prompt
    assert '"do_not_drop_or_rewrite_deterministic_attack_refs": true' in bundle.user_prompt
    assert '"preserve_explicit_branching_logic": true' in bundle.user_prompt
    assert '"use_and_operator_for_multi_step_sets": true' in bundle.user_prompt
    assert '"prefer_linked_objects_over_actions": true' in bundle.user_prompt
    assert '"output_shape_reminder": {' in bundle.user_prompt
    assert '"top_level_fields": [' in bundle.user_prompt
    assert '"technique_id": "T1059"' in bundle.user_prompt
    assert '"preserve_explicit_attack_evidence": true' in bundle.user_prompt


def test_empty_extraction_reprompt_is_stricter() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Execution phase\nC2 communication\nLateral movement",
        }
    )

    bundle = build_prompt_template_bundle(packaged)
    retry_bundle = build_empty_extraction_reprompt_bundle(packaged, source_cues=["C2 communication"])

    assert "extract every clearly supported attack action" in retry_bundle.user_prompt
    assert "Do not return an empty attack_actions array" in retry_bundle.user_prompt
    assert retry_bundle.system_instruction == bundle.system_instruction


def test_prompt_bundle_includes_afb_schema() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Observed command: ipconfig",
        }
    )

    bundle = build_prompt_template_bundle(packaged)

    assert isinstance(bundle.output_schema, dict)
    assert "properties" in bundle.output_schema
    assert "attack_flow" in bundle.output_schema["properties"]
    assert "attack_actions" in bundle.output_schema["properties"]
