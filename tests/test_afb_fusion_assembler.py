from attack_flow_api.services.afb_extraction_contracts import (
    AttackFlowMetadata,
    AfbExtractionResult,
    AttackAssetNode,
    AttackOperatorNode,
    OrchestrationMode,
    SourceClassification,
)
from attack_flow_api.services.afb_fusion_assembler import (
    FusedOutputCandidate,
    build_fused_output_candidate,
    build_fused_output_candidate_from_sources,
)
from attack_flow_api.services.afb_fusion_contracts import (
    FusionConflictCategory,
    FusionConflictRecord,
    FusionInputSourceKind,
)
from attack_flow_api.services.afb_fusion_dedup import (
    MergedAttackAction,
    MergedAttackRef,
    MergedAttachmentBundle,
    MergedEntity,
    MergedRelationship,
    MergedOperator,
)
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.repositories import JobCreate
from pathlib import Path


def test_build_fused_output_candidate_assembles_downstream_ready_shape() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--1",
        name="Example flow",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
        authors=["analyst-a"],
        external_references=["https://example.com/a"],
    )
    attack_refs = [
        MergedAttackRef(
            technique_id="T1059",
            source_object_id="attack-pattern--1",
            confidence=1.0,
        )
    ]
    entities = [
        MergedEntity(
            object_id="malware--1",
            object_type="malware",
            display_name="Malware",
            confidence=0.8,
        )
    ]
    relationships = [
        MergedRelationship(
            relationship_id="relationship--1",
            relationship_type="uses",
            source_ref="threat-actor--1",
            target_ref="malware--1",
            source_object_type="threat-actor",
            confidence=1.0,
        )
    ]
    actions = [
        MergedAttackAction(
            id="attack-action--1",
            name="Deterministic step",
            description="Observed command exactly as reported.",
            confidence=0.9,
            object_refs=["malware--1"],
            evidence=[
                {
                    "source": "narrative",
                    "excerpt": "Observed command exactly as reported.",
                }
            ],
        )
    ]
    attachment_bundle = MergedAttachmentBundle(
        attack_flow_authors=["analyst-a", "analyst-b"],
        attack_flow_external_references=["https://example.com/a", "https://example.com/b"],
        attack_actions=actions,
        attack_assets=entities,
        preserved_object_refs=["malware--1", "threat-actor--1"],
        preserved_evidence_refs=["report--1"],
    )

    candidate = build_fused_output_candidate(
        attack_flow=attack_flow,
        attack_refs=attack_refs,
        entities=entities,
        relationships=relationships,
        attack_actions=actions,
        attack_conditions=[],
        attack_operators=[],
        attachment_bundle=attachment_bundle,
        conflicts=[
            FusionConflictRecord(
                category=FusionConflictCategory.DUPLICATE_ATTACK_REF,
                source_kind=FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                message="duplicate attack ref",
                deterministic_ref="attack-pattern--1",
                unresolved=True,
            )
        ],
    )

    payload = candidate.to_json_ready()
    assert payload["schema_version"] == "afb-v2-fused-candidate"
    assert payload["fusion_validation_state"] == "ready"
    assert payload["attack_flow"]["authors"] == ["analyst-a", "analyst-b"]
    assert payload["attack_flow"]["external_references"] == ["https://example.com/a", "https://example.com/b"]
    assert payload["attack_refs"][0]["technique_id"] == "T1059"
    assert payload["entities"][0]["object_id"] == "malware--1"
    assert payload["relationships"][0]["relationship_id"] == "relationship--1"
    assert payload["attack_actions"][0]["description"] == "Observed command exactly as reported."
    assert payload["attack_assets"][0]["object_id"] == "malware--1"
    assert payload["source_grounded_attachments"]["preserved_object_refs"] == ["malware--1", "threat-actor--1"]
    assert payload["provenance"]["relationship_ids"] == ["relationship--1"]
    assert payload["conflicts"][0]["category"] == "duplicate_attack_ref"


def test_build_fused_output_candidate_accepts_attack_assets_without_object_type() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--asset",
        name="Asset example",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
    )

    extraction_result = AfbExtractionResult(
        validation_state="valid",
        provider_invoked=True,
        attack_flow=attack_flow,
        attack_assets=[
            AttackAssetNode(
                id="attack-asset--1",
                name="Runtime artifact",
                confidence=0.5,
            )
        ],
    )

    candidate = build_fused_output_candidate_from_sources(normalized_package={}, extraction_result=extraction_result)

    payload = candidate.to_json_ready()
    assert payload["attack_assets"][0]["object_type"] == "attack-asset"


def test_fused_output_candidate_remains_compatible_with_constrained_canonical_model() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--2",
        name="Example flow",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
    )

    candidate = build_fused_output_candidate(attack_flow=attack_flow)
    round_tripped = FusedOutputCandidate.model_validate_json(candidate.model_dump_json())

    assert round_tripped.schema_version == "afb-v2-fused-candidate"
    assert round_tripped.fusion_validation_state == "ready"
    assert round_tripped.attack_flow.id == "attack-flow--2"


def test_build_fused_output_candidate_backfills_operator_provenance() -> None:
    attack_flow = AttackFlowMetadata(
        id="attack-flow--operator",
        name="Example flow",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
    )

    extraction_result = AfbExtractionResult(
        validation_state="valid",
        provider_invoked=True,
        attack_flow=attack_flow,
        attack_operators=[
            AttackOperatorNode(
                id="operator--1",
                operator="OR",
                confidence=0.5,
                evidence=[{"source": "legacy_output", "excerpt": "A or B"}],
            )
        ],
    )

    candidate = build_fused_output_candidate_from_sources(normalized_package={}, extraction_result=extraction_result)

    payload = candidate.to_json_ready()
    assert payload["attack_operators"][0]["provenance"][0]["source_label"] == "ai_generated"


def test_persist_fused_output_candidate_writes_job_fusion_fields(tmp_path: Path) -> None:
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)
    service.create_job(JobCreate(id="job-1", status="queued", stage="queued"))

    attack_flow = AttackFlowMetadata(
        id="attack-flow--1",
        name="Example flow",
        scope="incident",
        orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
        source_classification=SourceClassification.STIX_STRUCTURED,
    )
    candidate = build_fused_output_candidate(attack_flow=attack_flow)

    updated = service.persist_fused_output_candidate("job-1", candidate)

    assert updated is not None
    assert updated.fusion_validation_state == "ready"
    assert updated.fusion_result_json is not None
    assert updated.fusion_result_json.startswith("{")
    assert updated.fusion_provenance_json is not None
    assert updated.fusion_conflicts_json == "[]"
