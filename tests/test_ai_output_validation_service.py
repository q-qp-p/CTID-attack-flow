from attack_flow_api.services.ai_orchestration_planner import build_provider_orchestration_input
from attack_flow_api.services.ai_output_validation_service import parse_validate_and_repair_extraction_output
from attack_flow_api.services.ai_provider_invocation_service import ProviderInvocationResult


def _packaged_input():
    return build_provider_orchestration_input(
        {
            "source_type": "stix_structured",
            "normalized_text": "",
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
        }
    )


def test_parse_validate_success_with_structured_json() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "provider_id": "default-openai",
        "model": "gpt-4.1-mini",
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Credential Access",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "technique": {
                    "technique_id": "T1059",
                    "confidence": 1.0,
                    "grounded_by": "explicit_attack_id_in_source",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
                "object_refs": ["malware--1", "malware--unknown"],
            }
        ],
        "attack_assets": [
            {
                "id": "attack-asset--1",
                "name": "Asset",
                "confidence": 0.9,
                "object_ref": "malware--unknown",
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.deterministic_attack_refs[0]["technique_id"] == "T1059"
    assert result.extraction_result.deterministic_attack_refs[0]["confidence"] == 1.0
    assert result.extraction_result.deterministic_attack_refs[0]["fact_origin"] == "deterministic_source"
    assert result.extraction_result.attack_actions[0].fact_origin.value == "ai_generated"
    assert result.extraction_result.attack_actions[0].object_refs == ["malware--1"]
    assert result.extraction_result.attack_assets[0].object_ref is None


def test_repair_attempt_parses_json_from_fenced_block() -> None:
    packaged = _packaged_input()
    output_text = """```json
{
  "validation_state": "valid",
  "provider_invoked": true,
  "provider_id": "default-openai",
  "model": "gpt-4.1-mini",
  "attack_flow": {
    "id": "attack-flow--1",
    "name": "Example flow",
    "scope": "incident",
    "start_refs": ["attack-action--1"],
    "orchestration_mode": "ai_enrichment",
    "source_classification": "stix_structured"
  },
  "attack_actions": [
    {
      "id": "attack-action--1",
      "name": "Credential Access",
      "description": "Observed command exactly as reported.",
      "confidence": 0.8,
      "evidence": [{"source": "narrative", "excerpt": "Observed command exactly as reported."}]
    }
  ]
}
```"""
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=None,
        output_text=output_text,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.repair_attempted is True
    assert result.extraction_result is not None
    assert result.extraction_result.repair_attempted is True


def test_preserves_authors_and_external_references_lists() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "stix_structured",
            "normalized_text": "",
            "metadata": {
                "authors": ["analyst-a", "analyst-b"],
                "external_references": ["https://example.com/a", "https://example.com/b"],
            },
            "structured_summary": {"bundle_metadata": {"id": "bundle--1"}},
        }
    )
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
            "authors": ["analyst-a"],
            "external_references": ["https://example.com/a"],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_flow.authors == ["analyst-a", "analyst-b"]
    assert result.extraction_result.attack_flow.external_references == [
        "https://example.com/a",
        "https://example.com/b",
    ]


def test_validation_fails_when_description_not_verbatim_evidence() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Credential Access",
                "description": "Paraphrased summary",
                "confidence": 0.8,
                "evidence": [{"source": "narrative", "excerpt": "Observed command exactly as reported."}],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is False
    assert result.error_code == "action_description_not_verbatim_excerpt"


def test_provider_error_is_returned_cleanly() -> None:
    packaged = _packaged_input()
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        error_code="provider_rate_limited",
        error_category="rate_limit",
        error_message="provider rate limit exceeded",
        retryable=True,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is False
    assert result.error_code == "provider_rate_limited"


def test_unrecoverable_malformed_output_fails_cleanly() -> None:
    packaged = _packaged_input()
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=None,
        output_text="not-json-and-no-object-braces",
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is False
    assert result.repair_attempted is True
    assert result.error_code == "extraction_output_malformed"


def test_steps_without_techniques_are_preserved() -> None:
    packaged = _packaged_input()
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "attack_flow": {
            "id": "attack-flow--1",
            "name": "Example flow",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "orchestration_mode": "ai_enrichment",
            "source_classification": "stix_structured",
        },
        "attack_actions": [
            {
                "id": "attack-action--1",
                "name": "Unmapped step",
                "description": "Observed command exactly as reported.",
                "confidence": 0.6,
                "evidence": [{"source": "narrative", "excerpt": "Observed command exactly as reported."}],
            }
        ],
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-4.1-mini",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_actions[0].technique is None
