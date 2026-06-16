from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    AttackActionNode,
    AttackAssetNode,
    AttackConditionNode,
    AttackFlowMetadata,
    AttackOperatorNode,
    AttackOperatorType,
    ConditionValue,
    ExtractionValidationState,
    FactOrigin,
    OrchestrationMode,
    SourceClassification,
    TechniqueGrounding,
)
from attack_flow_api.services.afb_fusion_assembler import FusedOutputCandidate
from attack_flow_api.services.afb_fusion_contracts import (
    FusionConflictCategory,
    FusionConflictRecord,
    FusionFindingProvenance,
    FusionInputSourceKind,
    FusionProvenanceKind,
)
from attack_flow_api.services.afb_fusion_dedup import (
    MergedAttackAction,
    MergedAttackRef,
    MergedAttachmentBundle,
    MergedCondition,
    MergedEntity,
    MergedOperator,
    MergedRelationship,
)
from attack_flow_api.services.canonical_flow_conversion_service import build_canonical_flow_output
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowEdgeKind,
    CanonicalFlowNodeKind,
    CanonicalFlowProvenanceKind,
)


def test_conversion_from_fused_output_preserves_flow_and_conflicts() -> None:
    fused = FusedOutputCandidate(
        attack_flow=AttackFlowMetadata(
            id="attack-flow--1",
            name="Example flow",
            scope="incident",
            description="Flow description.",
            orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
            source_classification=SourceClassification.STIX_STRUCTURED,
            start_refs=["attack-action--1"],
            authors=["analyst-a"],
            external_references=["https://example.com/report"],
            provenance={"source": "fused"},
        ),
        attack_refs=[
            MergedAttackRef(
                technique_id="T1059",
                source_object_id="attack-pattern--1",
                source_field="external_references[0]",
                external_source_name="ATT&CK",
                external_url="https://attack.mitre.org/techniques/T1059/",
                confidence=1.0,
                deterministic_confidence=0.87,
                ai_confidences=[],
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.DETERMINISTIC,
                        source_label="deterministic-stix",
                        source_object_id="attack-pattern--1",
                        source_field="external_references[0]",
                        confidence=0.87,
                    )
                ],
                conflicts=[
                    FusionConflictRecord(
                        category=FusionConflictCategory.DUPLICATE_ATTACK_REF,
                        source_kind=FusionInputSourceKind.DETERMINISTIC_STIX_OPENCTI,
                        message="duplicate attack ref",
                        deterministic_ref="attack-pattern--1",
                    )
                ],
            )
        ],
        entities=[
            MergedEntity(
                object_id="malware--1",
                object_type="malware",
                display_name="Malware",
                description="Asset description.",
                confidence=0.8,
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.DETERMINISTIC,
                        source_label="deterministic-stix",
                        source_object_id="malware--1",
                    )
                ],
            )
        ],
        relationships=[
            MergedRelationship(
                relationship_id="relationship--1",
                relationship_type="uses",
                source_ref="threat-actor--1",
                target_ref="malware--1",
                source_object_type="threat-actor",
                confidence=1.0,
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.DETERMINISTIC,
                        source_label="deterministic-stix",
                        source_object_id="relationship--1",
                    )
                ],
            )
        ],
        attack_actions=[
            MergedAttackAction(
                id="attack-action--1",
                name="Example step",
                description="Observed command exactly as reported.",
                confidence=0.9,
                asset_refs=["malware--1"],
                effect_refs=["attack-condition--1"],
                evidence=[
                    {
                        "source": "narrative",
                        "excerpt": "Observed command exactly as reported.",
                        "citation": "report-1",
                        "source_object_id": "report--1",
                    }
                ],
                citations=["report-1"],
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.DETERMINISTIC,
                        source_label="deterministic-stix",
                        source_object_id="attack-action--1",
                    )
                ],
                conflicts=[
                    FusionConflictRecord(
                        category=FusionConflictCategory.CONFLICTING_DESCRIPTION,
                        source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION,
                        message="description conflict",
                        deterministic_ref="attack-action--1",
                        ai_ref="attack-action--ai",
                    )
                ],
            )
        ],
        attack_conditions=[
            MergedCondition(
                id="attack-condition--1",
                description="Observed branch decision exactly as reported.",
                value="true",
                confidence=0.8,
                on_true_refs=["attack-operator--1"],
                evidence=[
                    {
                        "source": "narrative",
                        "excerpt": "Observed branch decision exactly as reported.",
                    }
                ],
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.AI_DERIVED,
                        source_label="afb",
                        source_object_id="attack-condition--1",
                    )
                ],
            )
        ],
        attack_operators=[
            MergedOperator(
                id="attack-operator--1",
                operator="AND",
                confidence=0.7,
                effect_refs=["attack-action--1"],
                evidence=[
                    {
                        "source": "narrative",
                        "excerpt": "Observed branching exactly as reported.",
                    }
                ],
                provenance=[
                    FusionFindingProvenance(
                        kind=FusionProvenanceKind.AI_DERIVED,
                        source_label="afb",
                        source_object_id="attack-operator--1",
                    )
                ],
            )
        ],
        attack_assets=[],
        source_grounded_attachments=MergedAttachmentBundle(
            attack_flow_authors=["analyst-a"],
            attack_flow_external_references=["https://example.com/report"],
            attack_actions=[],
            attack_assets=[],
            preserved_object_refs=["malware--1"],
            preserved_evidence_refs=["report--1"],
        ),
        provenance={"source": "fused"},
        conflicts=[
            FusionConflictRecord(
                category=FusionConflictCategory.DUPLICATE_STEP,
                source_kind=FusionInputSourceKind.AI_AFB_EXTRACTION,
                message="duplicate step",
                deterministic_ref="attack-action--1",
            )
        ],
    )

    canonical = build_canonical_flow_output(fused_output=fused)

    assert canonical is not None
    assert canonical.metadata.flow_id == "attack-flow--1"
    assert canonical.metadata.authors == ["analyst-a"]
    assert canonical.metadata.external_references == ["https://example.com/report"]
    assert canonical.source_grounded_attachments.attack_flow_authors == ["analyst-a"]
    assert canonical.source_grounded_attachments.attack_flow_external_references == ["https://example.com/report"]
    assert canonical.source_grounded_attachments.preserved_object_refs == ["malware--1", "threat-actor--1"]
    assert canonical.source_grounded_attachments.attack_action_evidence_refs == ["report--1"]
    assert canonical.provenance["source_form"] == "afb-v2-fused-candidate"
    assert canonical.attack_refs[0].confidence == 1.0
    assert canonical.attack_refs[0].conflicts[0].category == FusionConflictCategory.DUPLICATE_ATTACK_REF
    assert canonical.nodes[0].node_kind == CanonicalFlowNodeKind.ATTACK_ASSET
    assert canonical.nodes[1].node_kind == CanonicalFlowNodeKind.ATTACK_ACTION
    assert canonical.nodes[1].description == "Observed command exactly as reported."
    assert canonical.nodes[1].evidence[0].excerpt == "Observed command exactly as reported."
    assert canonical.nodes[1].conflicts[0].category == FusionConflictCategory.CONFLICTING_DESCRIPTION
    assert canonical.nodes[2].node_kind == CanonicalFlowNodeKind.ATTACK_CONDITION
    assert canonical.nodes[2].condition_value == "true"
    assert canonical.nodes[3].node_kind == CanonicalFlowNodeKind.ATTACK_OPERATOR
    assert canonical.nodes[3].operator == "AND"
    assert {edge.edge_type for edge in canonical.edges} == {
        CanonicalFlowEdgeKind.ASSET,
        CanonicalFlowEdgeKind.EFFECT,
        CanonicalFlowEdgeKind.TRUE_BRANCH,
        CanonicalFlowEdgeKind.RELATIONSHIP,
    }
    assert canonical.edges[-1].relationship_type == "uses"
    assert canonical.conflicts[0].category == FusionConflictCategory.DUPLICATE_STEP


def test_conversion_falls_back_to_afb_output_when_no_fused_output_exists() -> None:
    extraction = AfbExtractionResult.model_validate(
        {
            "validation_state": ExtractionValidationState.VALID,
            "provider_invoked": True,
            "attack_flow": AttackFlowMetadata(
                id="attack-flow--afb",
                name="AFB flow",
                scope="incident",
                description="AFB flow description.",
                orchestration_mode=OrchestrationMode.AI_ENRICHMENT,
                source_classification=SourceClassification.STIX_STRUCTURED,
                start_refs=["attack-action--afb"],
                authors=["analyst-b"],
                external_references=["https://example.com/afb"],
                provenance={"source": "afb"},
            ).model_dump(mode="json"),
            "attack_actions": [
                AttackActionNode(
                    id="attack-action--afb",
                    name="AFB step",
                    description="Observed command exactly as reported.",
                    confidence=0.75,
                    technique=TechniqueGrounding(
                        technique_id="T1059",
                        technique_name="Command and Scripting Interpreter",
                        confidence=0.75,
                        grounded_by="explicit_attack_id_in_source",
                    ),
                    evidence=[
                        {
                            "source": "narrative",
                            "excerpt": "Observed command exactly as reported.",
                            "citation": "report-2",
                        }
                    ],
                    citations=["report-2"],
                    fact_origin=FactOrigin.DETERMINISTIC_SOURCE,
                ).model_dump(mode="json"),
            ],
            "attack_conditions": [
                AttackConditionNode(
                    id="attack-condition--afb",
                    description="Observed branch decision exactly as reported.",
                    value=ConditionValue.TRUE,
                    confidence=0.6,
                    on_true_refs=["attack-operator--afb"],
                    evidence=[
                        {
                            "source": "narrative",
                            "excerpt": "Observed branch decision exactly as reported.",
                        }
                    ],
                    fact_origin=FactOrigin.AI_GENERATED,
                ).model_dump(mode="json"),
            ],
            "attack_operators": [
                AttackOperatorNode(
                    id="attack-operator--afb",
                    operator=AttackOperatorType.AND,
                    confidence=0.5,
                    effect_refs=["attack-action--afb"],
                    evidence=[
                        {
                            "source": "narrative",
                            "excerpt": "Observed branching exactly as reported.",
                        }
                    ],
                    fact_origin=FactOrigin.AI_GENERATED,
                ).model_dump(mode="json"),
            ],
            "attack_assets": [
                AttackAssetNode(
                    id="attack-asset--afb",
                    name="AFB asset",
                    object_ref="malware--afb",
                    evidence=[
                        {
                            "source": "narrative",
                            "excerpt": "Observed asset attachment exactly as reported.",
                        }
                    ],
                    confidence=0.4,
                    fact_origin=FactOrigin.AI_GENERATED,
                ).model_dump(mode="json"),
            ],
            "deterministic_attack_refs": [
                {
                    "technique_id": "T1059",
                    "source_object_id": "attack-pattern--afb",
                    "source_field": "external_references[0]",
                }
            ],
            "deterministic_relationships": [
                {
                    "relationship_id": "relationship--afb",
                    "relationship_type": "uses",
                    "source_ref": "threat-actor--afb",
                    "target_ref": "malware--afb",
                    "source_object_type": "threat-actor",
                }
            ],
        }
    )

    canonical = build_canonical_flow_output(fused_output=None, extraction_output=extraction)

    assert canonical is not None
    assert canonical.metadata.flow_id == "attack-flow--afb"
    assert canonical.metadata.authors == ["analyst-b"]
    assert canonical.source_grounded_attachments.attack_flow_authors == ["analyst-b"]
    assert canonical.source_grounded_attachments.attack_flow_external_references == ["https://example.com/afb"]
    assert canonical.source_grounded_attachments.preserved_object_refs == ["malware--afb", "threat-actor--afb"]
    assert canonical.attack_refs[0].confidence == 1.0
    assert canonical.nodes[1].technique is not None
    assert canonical.nodes[1].technique.technique_name == "Command and Scripting Interpreter"
    assert canonical.attack_refs[0].source_object_id == "attack-pattern--afb"
    assert canonical.nodes[0].node_kind == CanonicalFlowNodeKind.ATTACK_ASSET
    assert canonical.nodes[1].node_kind == CanonicalFlowNodeKind.ATTACK_ACTION
    assert canonical.nodes[1].provenance[0].source_kind == CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT
    assert canonical.nodes[2].node_kind == CanonicalFlowNodeKind.ATTACK_CONDITION
    assert canonical.nodes[2].provenance[0].source_kind == CanonicalFlowProvenanceKind.AI_ASSISTED_ADDITION
    assert canonical.edges[-1].edge_type == CanonicalFlowEdgeKind.RELATIONSHIP
    assert canonical.edges[-1].relationship_type == "uses"
    assert canonical.provenance["source_form"] == "afb-v2-intermediate"
