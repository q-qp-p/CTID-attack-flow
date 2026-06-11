from attack_flow_api.services.ai_orchestration_planner import build_provider_orchestration_input
from attack_flow_api.services.ai_prompt_templates import build_prompt_template_bundle


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
    assert "Never infer missing ATT&CK techniques" in bundle.system_instruction
    assert "attack-action descriptions must be verbatim source excerpts only" in bundle.system_instruction
    assert "AND or OR" in bundle.system_instruction
    assert "true or false" in bundle.system_instruction
    assert "PACKAGED_INPUT" in bundle.user_prompt
    assert '"mode": "full_extraction"' in bundle.user_prompt
    assert '"allow_actions_without_techniques": true' in bundle.user_prompt


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
    assert '"preserve_deterministic_findings": true' in bundle.user_prompt
    assert '"do_not_drop_or_rewrite_deterministic_attack_refs": true' in bundle.user_prompt
    assert '"technique_id": "T1059"' in bundle.user_prompt


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
