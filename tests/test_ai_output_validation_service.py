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


def test_parse_validate_accepts_technique_name_only() -> None:
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
                "name": "Command execution",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "technique": {
                    "technique_name": "Command and Scripting Interpreter",
                    "confidence": 0.75,
                    "grounded_by": "legacy_attack_term_mapped_to_v19_1",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
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
    assert result.extraction_result.attack_actions[0].technique is not None
    assert result.extraction_result.attack_actions[0].technique.technique_name == "Command and Scripting Interpreter"


def test_parse_validate_promotes_highest_confidence_technique_from_plural_field() -> None:
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
                "name": "Command execution",
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "techniques": [
                    {
                        "attack_object": {"id": "T1059.001", "name": "PowerShell"},
                        "confidence": 0.75,
                        "grounded_by": "PowerShell command",
                    },
                    {
                        "attack_object": {"id": "T1105", "name": "Ingress Tool Transfer"},
                        "confidence": 0.91,
                        "grounded_by": "downloadstring from a remote URL",
                    },
                ],
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
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
    assert result.extraction_result.attack_actions[0].technique is not None
    assert result.extraction_result.attack_actions[0].technique.technique_id == "T1105"
    assert result.extraction_result.attack_actions[0].technique.technique_name == "Ingress Tool Transfer"


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


def test_parse_validate_accepts_legacy_attack_flow_objects_envelope() -> None:
    packaged = _packaged_input()
    output_json = {
        "type": "afb-extraction",
        "source_name": "Example report",
        "source_type": "document_extracted_text",
        "attack_version": "19.1",
        "authors": ["analyst-a"],
        "external_references": ["https://example.com/report"],
        "metadata": {
            "mode": "full_extraction",
            "title": "Example report",
        },
        "attack_flow": {
            "type": "attack-flow",
            "name": "Example report",
            "description": "Legacy envelope shape",
            "scope": "incident",
            "start_refs": ["attack-action--1"],
            "objects": [
                {
                    "type": "attack-action",
                    "id": "attack-action--1",
                    "name": "Phishing link",
                    "description": "Clicked a phishing link.",
                    "confidence": 0.9,
                    "evidence": [{"source": "report", "excerpt": "Clicked a phishing link."}],
                }
            ],
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
    assert result.extraction_result.attack_flow.name == "Example report"
    assert result.extraction_result.attack_flow.provenance["source_name"] == "Example report"
    assert result.extraction_result.attack_actions[0].name == "Phishing link"


def test_parse_validate_unwraps_nested_output_json_wrapper() -> None:
    packaged = _packaged_input()
    output_json = {
        "job_id": "job--1",
        "label": "retry",
        "mode": "full_extraction",
        "source_type": "document_extracted_text",
        "provider_id": "default-openai",
        "model_used": "gpt-5.4",
        "output_json": {
            "validation_state": "valid",
            "provider_invoked": True,
            "attack_flow": {
                "id": "attack-flow--1",
                "name": "Wrapped example",
                "scope": "incident",
                "start_refs": ["attack-action--1"],
                "orchestration_mode": "full_extraction",
                "source_classification": "document_extracted_text",
            },
            "attack_actions": [
                {
                    "id": "attack-action--1",
                    "name": "Phishing link",
                    "description": "Clicked a phishing link.",
                    "confidence": 0.9,
                    "evidence": [{"source": "report", "excerpt": "Clicked a phishing link."}],
                }
            ],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_flow.name == "Wrapped example"
    assert result.extraction_result.attack_actions[0].id == "attack-action--1"


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


def test_invalid_groundings_are_dropped_before_validation() -> None:
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
                "description": "Observed command exactly as reported.",
                "confidence": 0.8,
                "technique": {
                    "technique_id": None,
                    "technique_ref": None,
                    "confidence": 0.9,
                    "grounded_by": "strongly implied",
                },
                "tactic": {
                    "tactic_id": None,
                    "tactic_ref": None,
                    "confidence": 0.8,
                    "grounded_by": "strongly implied",
                },
                "evidence": [
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                    }
                ],
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
    assert result.extraction_result.attack_actions[0].tactic is None


def test_legacy_afb_extraction_envelope_is_coerced() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Observed command: whoami",
            "metadata": {"title": "Legacy example", "authors": ["analyst-a"]},
        }
    )
    output_json = {
        "type": "afb-extraction",
        "version": "1.0",
        "source": {
            "source_type": "document_extracted_text",
            "file_class": "pdf",
            "mime_type": "application/pdf",
            "original_name": "example.pdf",
        },
        "metadata": {"title": "Legacy example", "authors": ["analyst-a"], "mode": "enrichment"},
        "deterministic_findings": {
            "attack_refs": [{"technique_id": "T1059", "source_object_id": "attack-pattern--1"}],
            "entities": [],
            "relationships": [],
        },
        "external_references": ["https://example.com/ref"],
        "attack_flow": {
            "attack_operator": "AND",
            "attack_condition": "true",
            "steps": [
                {
                    "step_id": "step-1",
                    "description": "Observed command: whoami",
                    "confidence": 0.9,
                    "evidence": [{"source": "report", "excerpt": "Observed command: whoami"}],
                }
            ],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.provider_invoked is True
    assert result.extraction_result.attack_flow.name == "Legacy example"
    assert result.extraction_result.attack_actions[0].id == "step-1"
    assert result.extraction_result.attack_actions[0].description == "Observed command: whoami"
    assert result.extraction_result.attack_operators[0].operator.value == "AND"


def test_legacy_attack_flow_objects_shape_is_coerced() -> None:
    packaged = build_provider_orchestration_input(
        {
            "source_type": "narrative_text",
            "normalized_text": "Observed command: whoami",
            "metadata": {"title": "Legacy objects example"},
        }
    )
    output_json = {
        "validation_state": "valid",
        "provider_invoked": True,
        "source_name": "Cybereason Labs Analysis Operation Cobalt Kitty-Part1.pdf",
        "source_type": "document_extracted_text",
        "attack_version": "19.1",
        "authors": ["Assaf Dahan"],
        "external_references": ["https://example.com/ref"],
        "attack_flow": {
            "type": "attack-flow",
            "name": "Legacy objects example",
            "objects": [
                {
                    "id": "action-1",
                    "type": "attack-action",
                    "name": "step-01",
                    "description": "Observed command: whoami",
                    "confidence": 0.95,
                    "evidence": [{"source": "report", "excerpt": "Observed command: whoami"}],
                },
                {
                    "id": "operator-1",
                    "type": "attack-operator",
                    "operator": "OR",
                    "confidence": 0.9,
                    "effect_refs": ["action-1"],
                },
            ],
        },
    }
    invocation_result = ProviderInvocationResult(
        provider_invoked=True,
        provider_id="default-openai",
        model_used="gpt-5.4",
        deterministic_input_sufficient=False,
        output_json=output_json,
    )

    result = parse_validate_and_repair_extraction_output(
        invocation_result=invocation_result,
        packaged_input=packaged,
    )

    assert result.valid is True
    assert result.extraction_result is not None
    assert result.extraction_result.attack_flow.name == "Legacy objects example"
    assert result.extraction_result.attack_flow.authors == ["Assaf Dahan"]
    assert result.extraction_result.attack_actions[0].id == "action-1"
    assert result.extraction_result.attack_operators[0].id == "operator-1"
