from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from attack_flow_api.services.afb_extraction_contracts import (
    AfbExtractionResult,
    AttackActionNode,
    AttackAssetNode,
    AttackConditionNode,
    AttackOperatorNode,
    FactOrigin,
    SourceClassification,
)
from attack_flow_api.services.afb_fusion_assembler import FusedOutputCandidate
from attack_flow_api.services.afb_fusion_contracts import FusionConflictRecord, FusionFindingProvenance, FusionProvenanceKind
from attack_flow_api.services.afb_fusion_dedup import (
    MergedAttackAction,
    MergedAttackRef,
    MergedEntity,
    MergedRelationship,
)
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowAttachmentBundle,
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowConditionNode,
    CanonicalFlowEdge,
    CanonicalFlowEdgeKind,
    CanonicalFlowEvidenceRecord,
    CanonicalFlowMetadata,
    CanonicalFlowNode,
    CanonicalFlowNodeKind,
    CanonicalFlowOperatorNode,
    CanonicalFlowOutput,
    CanonicalFlowProvenanceKind,
    CanonicalFlowProvenanceRecord,
    CanonicalFlowSourceClassification,
    CanonicalFlowTechniqueReference,
)


class CanonicalFlowConversionService:
    def build_canonical_flow_output(
        self,
        *,
        fused_output: FusedOutputCandidate | None = None,
        extraction_output: AfbExtractionResult | None = None,
    ) -> CanonicalFlowOutput | None:
        if fused_output is not None:
            return self.from_fused_output(fused_output)
        if extraction_output is not None:
            return self.from_afb_extraction_output(extraction_output)
        return None

    def from_fused_output(self, fused_output: FusedOutputCandidate) -> CanonicalFlowOutput:
        provenance = {
            **dict(fused_output.provenance),
            "source_form": fused_output.schema_version,
            "source_validation_state": fused_output.fusion_validation_state,
        }
        attack_refs = [
            _convert_attack_ref(ref, source_classification=fused_output.attack_flow.source_classification)
            for ref in fused_output.attack_refs
        ]
        nodes = [
            *_convert_entities_to_assets(fused_output.entities),
            *_convert_actions(fused_output.attack_actions),
            *_convert_conditions(fused_output.attack_conditions),
            *_convert_operators(fused_output.attack_operators),
        ]
        metadata = _build_metadata_from_attack_flow(
            fused_output.attack_flow,
            provenance=provenance,
            start_refs=_filter_start_refs(fused_output.attack_flow, nodes),
        )
        edges = _build_edges_from_fused_output(nodes, fused_output.attack_actions, fused_output.attack_conditions, fused_output.attack_operators, fused_output.attack_assets, fused_output.relationships)

        return _build_canonical_flow_output(
            metadata=metadata,
            attack_refs=attack_refs,
            source_grounded_attachments=_build_attachment_bundle_from_fused_output(
                fused_output,
                metadata.authors,
                metadata.external_references,
            ),
            nodes=nodes,
            edges=edges,
            provenance=provenance,
            conflicts=list(fused_output.conflicts),
            authors=list(metadata.authors),
            external_references=list(metadata.external_references),
        )

    def from_afb_extraction_output(self, extraction_output: AfbExtractionResult) -> CanonicalFlowOutput:
        provenance = {
            **dict(extraction_output.attack_flow.provenance),
            "source_form": extraction_output.schema_version,
            "source_validation_state": extraction_output.validation_state.value,
            "repair_attempted": extraction_output.repair_attempted,
            "provider_invoked": extraction_output.provider_invoked,
        }
        attack_refs = [
            _convert_attack_ref_from_dict(ref, source_classification=extraction_output.attack_flow.source_classification)
            for ref in extraction_output.deterministic_attack_refs
        ]
        nodes = [
            *_convert_afb_assets(extraction_output.attack_assets),
            *_convert_afb_actions(extraction_output.attack_actions),
            *_convert_afb_conditions(extraction_output.attack_conditions),
            *_convert_afb_operators(extraction_output.attack_operators),
        ]
        metadata = _build_metadata_from_attack_flow(
            extraction_output.attack_flow,
            provenance=provenance,
            start_refs=_filter_start_refs(extraction_output.attack_flow, nodes),
        )
        edges = _build_edges_from_afb_output(
            nodes,
            extraction_output.attack_actions,
            extraction_output.attack_conditions,
            extraction_output.attack_operators,
            extraction_output.attack_assets,
            extraction_output.deterministic_relationships,
        )

        return _build_canonical_flow_output(
            metadata=metadata,
            attack_refs=attack_refs,
            source_grounded_attachments=_build_attachment_bundle_from_afb_output(
                extraction_output,
                metadata.authors,
                metadata.external_references,
            ),
            nodes=nodes,
            edges=edges,
            provenance=provenance,
            conflicts=[],
            authors=list(metadata.authors),
            external_references=list(metadata.external_references),
        )


def build_canonical_flow_output(
    *,
    fused_output: FusedOutputCandidate | None = None,
    extraction_output: AfbExtractionResult | None = None,
) -> CanonicalFlowOutput | None:
    return CanonicalFlowConversionService().build_canonical_flow_output(
        fused_output=fused_output,
        extraction_output=extraction_output,
    )


def _build_canonical_flow_output(
    *,
    metadata: CanonicalFlowMetadata,
    attack_refs: list[CanonicalFlowTechniqueReference],
    source_grounded_attachments: CanonicalFlowAttachmentBundle,
    nodes: list[CanonicalFlowNode],
    edges: list[CanonicalFlowEdge],
    provenance: dict[str, Any],
    conflicts: list[FusionConflictRecord],
    authors: list[str],
    external_references: list[str],
) -> CanonicalFlowOutput:
    return CanonicalFlowOutput(
        metadata=metadata,
        attack_refs=attack_refs,
        source_grounded_attachments=source_grounded_attachments,
        nodes=nodes,
        edges=edges,
        provenance=provenance,
        conflicts=conflicts,
        validation_state="pending",
        validation_errors=[],
        authors=authors,
        external_references=external_references,
    )


def _build_metadata_from_attack_flow(
    attack_flow: Any,
    *,
    provenance: dict[str, Any],
    start_refs: list[str] | None = None,
) -> CanonicalFlowMetadata:
    source_classification = _coerce_source_classification(getattr(attack_flow, "source_classification", None))
    return CanonicalFlowMetadata(
        flow_id=_as_str(getattr(attack_flow, "id", None)) or "attack-flow--unknown",
        name=_as_str(getattr(attack_flow, "name", None)) or "",
        scope=_as_str(getattr(attack_flow, "scope", None)) or "other",
        description=_as_str(getattr(attack_flow, "description", None)),
        start_refs=start_refs if start_refs is not None else _as_str_list(getattr(attack_flow, "start_refs", None)),
        authors=_as_str_list(getattr(attack_flow, "authors", None)),
        external_references=_as_str_list(getattr(attack_flow, "external_references", None)),
        provenance={
            **provenance,
            "source_classification": source_classification.value if source_classification else None,
        },
    )


def _build_attachment_bundle_from_fused_output(
    fused_output: FusedOutputCandidate,
    authors: list[str],
    external_references: list[str],
) -> CanonicalFlowAttachmentBundle:
    attack_asset_refs = _dedupe_preserve_order(
        [
            ref
            for asset in fused_output.attack_assets
            for ref in [asset.object_id, asset.source_ref, asset.target_ref]
            if ref
        ]
        + [
            ref
            for asset in fused_output.source_grounded_attachments.attack_assets
            for ref in [asset.object_id, asset.source_ref, asset.target_ref]
            if ref
        ]
    )
    attack_action_object_refs = _dedupe_preserve_order(
        [ref for action in fused_output.attack_actions for ref in action.object_refs if ref]
        + [ref for action in fused_output.source_grounded_attachments.attack_actions for ref in action.object_refs if ref]
    )
    attack_action_evidence_refs = _dedupe_preserve_order(
        [
            _as_str(entry.get("source_object_id"))
            for action in fused_output.attack_actions
            for entry in action.evidence
            if isinstance(entry, Mapping) and _as_str(entry.get("source_object_id"))
        ]
        + [
            _as_str(entry.get("source_object_id"))
            for action in fused_output.source_grounded_attachments.attack_actions
            for entry in action.evidence
            if isinstance(entry, Mapping) and _as_str(entry.get("source_object_id"))
        ]
    )
    relationship_refs = _dedupe_preserve_order(
        [
            ref
            for relationship in fused_output.relationships
            for ref in [relationship.source_ref, relationship.target_ref]
            if ref
        ]
    )
    return CanonicalFlowAttachmentBundle(
        attack_flow_authors=list(fused_output.source_grounded_attachments.attack_flow_authors or authors),
        attack_flow_external_references=list(
            fused_output.source_grounded_attachments.attack_flow_external_references or external_references
        ),
        preserved_object_refs=_dedupe_preserve_order(
            list(fused_output.source_grounded_attachments.preserved_object_refs) + relationship_refs
        ),
        preserved_evidence_refs=list(fused_output.source_grounded_attachments.preserved_evidence_refs),
        attack_asset_refs=attack_asset_refs,
        attack_action_object_refs=attack_action_object_refs,
        attack_action_evidence_refs=attack_action_evidence_refs,
    )


def _build_attachment_bundle_from_afb_output(
    extraction_output: AfbExtractionResult,
    authors: list[str],
    external_references: list[str],
) -> CanonicalFlowAttachmentBundle:
    attack_asset_refs = [
        ref
        for asset in extraction_output.attack_assets
        for ref in [asset.object_ref]
        if ref
    ]
    action_object_refs = [
        ref
        for action in extraction_output.attack_actions
        for ref in action.object_refs
        if ref
    ]
    action_evidence_refs = [
        entry.source_object_id
        for action in extraction_output.attack_actions
        for entry in action.evidence
        if entry.source_object_id
    ]
    relationship_refs = [
        ref
        for relationship in extraction_output.deterministic_relationships
        for ref in [
            _as_str(relationship.get("source_ref")) if isinstance(relationship, Mapping) else "",
            _as_str(relationship.get("target_ref")) if isinstance(relationship, Mapping) else "",
        ]
        if ref
    ]
    preserved_refs = _dedupe_preserve_order([*attack_asset_refs, *action_object_refs, *action_evidence_refs, *relationship_refs])
    return CanonicalFlowAttachmentBundle(
        attack_flow_authors=list(authors),
        attack_flow_external_references=list(external_references),
        preserved_object_refs=preserved_refs,
        preserved_evidence_refs=_dedupe_preserve_order([ref for ref in action_evidence_refs if ref]),
        attack_asset_refs=attack_asset_refs,
        attack_action_object_refs=action_object_refs,
        attack_action_evidence_refs=[ref for ref in action_evidence_refs if ref],
    )


def _filter_start_refs(attack_flow: Any, nodes: list[CanonicalFlowNode]) -> list[str]:
    allowed_refs = {
        node.id
        for node in nodes
        if getattr(node, "node_kind", None)
        in {CanonicalFlowNodeKind.ATTACK_ACTION, CanonicalFlowNodeKind.ATTACK_CONDITION}
    }
    return [ref for ref in _as_str_list(getattr(attack_flow, "start_refs", None)) if ref in allowed_refs]


def _convert_attack_ref(
    ref: MergedAttackRef,
    *,
    source_classification: SourceClassification | None,
) -> CanonicalFlowTechniqueReference:
    provenance = [_convert_fusion_provenance(item) for item in ref.provenance]
    confidence = 1.0 if any(item.source_kind == CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT for item in provenance) else ref.confidence
    return CanonicalFlowTechniqueReference(
        technique_id=ref.technique_id,
        technique_ref=ref.technique_ref,
        technique_name=_as_str(getattr(ref, "technique_name", None)),
        source_object_id=ref.source_object_id,
        source_field=ref.source_field,
        source_classification=_coerce_source_classification(source_classification),
        confidence=confidence,
        provenance=provenance,
        evidence=[_build_attack_ref_evidence(ref)],
        conflicts=list(ref.conflicts),
    )


def _convert_attack_ref_from_dict(
    ref: Mapping[str, Any],
    *,
    source_classification: SourceClassification | None,
) -> CanonicalFlowTechniqueReference:
    confidence = _coerce_confidence(ref.get("confidence"), default=1.0)
    return CanonicalFlowTechniqueReference(
        technique_id=_as_str(ref.get("technique_id")),
        technique_ref=_as_str(ref.get("technique_ref")),
        technique_name=_as_str(ref.get("technique_name")),
        source_object_id=_as_str(ref.get("source_object_id")),
        source_field=_as_str(ref.get("source_field")),
        source_classification=_coerce_source_classification(source_classification),
        confidence=confidence,
        provenance=[
            CanonicalFlowProvenanceRecord(
                source_label=_as_str(ref.get("source_object_type")) or "deterministic_source",
                source_kind=CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT,
                source_object_id=_as_str(ref.get("source_object_id")),
                source_field=_as_str(ref.get("source_field")),
                confidence=confidence,
            )
        ],
        evidence=[_build_attack_ref_evidence_from_dict(ref)],
        conflicts=[],
    )


def _convert_actions(actions: list[MergedAttackAction]) -> list[CanonicalFlowActionNode]:
    return [
        CanonicalFlowActionNode(
            id=action.id,
            name=action.name,
            description=action.description,
            confidence=action.confidence,
            technique=_convert_technique_mapping(action.technique, action.provenance, action.confidence),
            tactic_ref=_as_str(_mapping_get(action.tactic, "tactic_ref")),
            tactic_name=_as_str(_mapping_get(action.tactic, "tactic_name")),
            asset_refs=list(action.asset_refs),
            object_refs=list(action.object_refs),
            effect_refs=list(action.effect_refs),
            evidence=[_convert_evidence_record(item) for item in action.evidence],
            citations=list(action.citations),
            provenance=[_convert_fusion_provenance(item) for item in action.provenance],
            conflicts=list(action.conflicts),
        )
        for action in actions
    ]


def _convert_afb_actions(actions: list[AttackActionNode]) -> list[CanonicalFlowActionNode]:
    return [
        CanonicalFlowActionNode(
            id=action.id,
            name=action.name,
            description=action.description,
            confidence=action.confidence,
            technique=_convert_technique_from_afb(action.technique, action.confidence),
            tactic_ref=_as_str(getattr(action.tactic, "tactic_ref", None)),
            tactic_name=_as_str(getattr(action.tactic, "tactic_name", None)),
            asset_refs=list(action.asset_refs),
            object_refs=list(action.object_refs),
            effect_refs=list(action.effect_refs),
            evidence=[_convert_evidence_record(item) for item in action.evidence],
            citations=list(action.citations),
            provenance=[_convert_fact_origin(action.fact_origin)],
            conflicts=[],
        )
        for action in actions
    ]


def _convert_conditions(conditions: list[MergedCondition]) -> list[CanonicalFlowConditionNode]:
    return [
        CanonicalFlowConditionNode(
            id=item.id,
            name=None,
            description=item.description,
            confidence=item.confidence,
            condition_value=item.value,  # type: ignore[arg-type]
            on_true_refs=list(item.on_true_refs),
            on_false_refs=list(item.on_false_refs),
            evidence=[_convert_evidence_dict(entry) for entry in item.evidence],
            citations=list(item.citations),
            provenance=[_convert_fusion_provenance(entry) for entry in item.provenance],
            conflicts=list(item.conflicts),
        )
        for item in conditions
    ]


def _convert_afb_conditions(conditions: list[AttackConditionNode]) -> list[CanonicalFlowConditionNode]:
    return [
        CanonicalFlowConditionNode(
            id=item.id,
            name=None,
            description=item.description,
            confidence=item.confidence,
            condition_value=item.value.value,
            on_true_refs=list(item.on_true_refs),
            on_false_refs=list(item.on_false_refs),
            evidence=[_convert_evidence_record(entry) for entry in item.evidence],
            citations=list(item.citations),
            provenance=[_convert_fact_origin(item.fact_origin)],
            conflicts=[],
        )
        for item in conditions
    ]


def _convert_operators(operators: list[MergedOperator]) -> list[CanonicalFlowOperatorNode]:
    return [
        CanonicalFlowOperatorNode(
            id=item.id,
            name=None,
            description=None,
            confidence=item.confidence,
            operator=item.operator,  # type: ignore[arg-type]
            effect_refs=list(item.effect_refs),
            evidence=[_convert_evidence_dict(entry) for entry in item.evidence],
            citations=list(item.citations),
            provenance=[_convert_fusion_provenance(entry) for entry in item.provenance],
            conflicts=list(item.conflicts),
        )
        for item in operators
    ]


def _convert_afb_operators(operators: list[AttackOperatorNode]) -> list[CanonicalFlowOperatorNode]:
    return [
        CanonicalFlowOperatorNode(
            id=item.id,
            name=None,
            description=None,
            confidence=item.confidence,
            operator=item.operator.value,
            effect_refs=list(item.effect_refs),
            evidence=[_convert_evidence_record(entry) for entry in item.evidence],
            citations=list(item.citations),
            provenance=[_convert_fact_origin(item.fact_origin)],
            conflicts=[],
        )
        for item in operators
    ]


def _convert_entities_to_assets(entities: list[MergedEntity]) -> list[CanonicalFlowAssetNode]:
    return [
        CanonicalFlowAssetNode(
            id=item.object_id or item.display_name or item.object_type,
            name=item.display_name or item.object_type,
            description=item.description,
            confidence=item.confidence,
            object_ref=item.object_id,
            evidence=[],
            citations=[],
            provenance=[_convert_fusion_provenance(entry) for entry in item.provenance],
            conflicts=list(item.conflicts),
        )
        for item in entities
    ]


def _convert_afb_assets(assets: list[AttackAssetNode]) -> list[CanonicalFlowAssetNode]:
    return [
        CanonicalFlowAssetNode(
            id=item.id,
            name=item.name,
            description=item.description,
            confidence=item.confidence,
            object_ref=item.object_ref,
            evidence=[_convert_evidence_record(entry) for entry in item.evidence],
            citations=[],
            provenance=[_convert_fact_origin(item.fact_origin)],
            conflicts=[],
        )
        for item in assets
    ]


def _build_edges_from_fused_output(
    nodes: list[CanonicalFlowNode],
    actions: list[MergedAttackAction],
    conditions: list[MergedCondition],
    operators: list[MergedOperator],
    assets: list[MergedEntity],
    relationships: list[MergedRelationship],
) -> list[CanonicalFlowEdge]:
    edges: list[CanonicalFlowEdge] = []
    for action in actions:
        for ref in action.asset_refs:
            edges.append(CanonicalFlowEdge(source_ref=action.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.ASSET))
        for ref in action.effect_refs:
            edges.append(CanonicalFlowEdge(source_ref=action.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.EFFECT))
    for condition in conditions:
        for ref in condition.on_true_refs:
            edges.append(CanonicalFlowEdge(source_ref=condition.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.TRUE_BRANCH))
        for ref in condition.on_false_refs:
            edges.append(CanonicalFlowEdge(source_ref=condition.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.FALSE_BRANCH))
    for operator in operators:
        for ref in operator.effect_refs:
            edges.append(CanonicalFlowEdge(source_ref=operator.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.EFFECT))
    for relationship in relationships:
        edges.append(
            CanonicalFlowEdge(
                source_ref=relationship.source_ref,
                target_ref=relationship.target_ref,
                edge_type=CanonicalFlowEdgeKind.RELATIONSHIP,
                relationship_type=relationship.relationship_type,
                confidence=relationship.confidence,
                provenance=[_convert_fusion_provenance(item) for item in relationship.provenance],
                conflicts=list(relationship.conflicts),
            )
        )
    return edges


def _build_edges_from_afb_output(
    nodes: list[CanonicalFlowNode],
    actions: list[AttackActionNode],
    conditions: list[AttackConditionNode],
    operators: list[AttackOperatorNode],
    assets: list[AttackAssetNode],
    relationships: list[dict[str, object]],
) -> list[CanonicalFlowEdge]:
    edges: list[CanonicalFlowEdge] = []
    for action in actions:
        for ref in action.asset_refs:
            edges.append(CanonicalFlowEdge(source_ref=action.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.ASSET))
        for ref in action.effect_refs:
            edges.append(CanonicalFlowEdge(source_ref=action.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.EFFECT))
    for condition in conditions:
        for ref in condition.on_true_refs:
            edges.append(CanonicalFlowEdge(source_ref=condition.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.TRUE_BRANCH))
        for ref in condition.on_false_refs:
            edges.append(CanonicalFlowEdge(source_ref=condition.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.FALSE_BRANCH))
    for operator in operators:
        for ref in operator.effect_refs:
            edges.append(CanonicalFlowEdge(source_ref=operator.id, target_ref=ref, edge_type=CanonicalFlowEdgeKind.EFFECT))
    for relationship in relationships:
        source_ref = _as_str(relationship.get("source_ref"))
        target_ref = _as_str(relationship.get("target_ref"))
        relationship_type = _as_str(relationship.get("relationship_type"))
        if source_ref and target_ref and relationship_type:
            edges.append(
                CanonicalFlowEdge(
                    source_ref=source_ref,
                    target_ref=target_ref,
                    edge_type=CanonicalFlowEdgeKind.RELATIONSHIP,
                    relationship_type=relationship_type,
                )
            )
    return edges


def _convert_technique_mapping(
    mapping: dict[str, Any] | None,
    provenance: list[FusionFindingProvenance],
    default_confidence: float,
) -> CanonicalFlowTechniqueReference | None:
    if mapping is None:
        return None
    confidence = _coerce_confidence(mapping.get("confidence"), default=default_confidence)
    return CanonicalFlowTechniqueReference(
        technique_id=_as_str(mapping.get("technique_id")),
        technique_ref=_as_str(mapping.get("technique_ref")),
        technique_name=_as_str(mapping.get("technique_name")),
        source_object_id=_as_str(mapping.get("source_object_id")),
        source_field=_as_str(mapping.get("source_field")),
        confidence=confidence,
        provenance=[_convert_fusion_provenance(item) for item in provenance],
        evidence=[
            CanonicalFlowEvidenceRecord(
                source=_as_str(mapping.get("grounded_by")) or "attack-technique",
                excerpt=_as_str(mapping.get("technique_id")) or _as_str(mapping.get("technique_ref")) or "attack-technique",
                confidence=confidence,
            )
        ],
        conflicts=[],
    )


def _convert_technique_from_afb(
    technique: Any,
    default_confidence: float,
) -> CanonicalFlowTechniqueReference | None:
    if technique is None:
        return None
    if hasattr(technique, "model_dump"):
        mapping = technique.model_dump(mode="json")
    elif isinstance(technique, dict):
        mapping = technique
    else:
        return None
    confidence = _coerce_confidence(mapping.get("confidence"), default=default_confidence)
    return CanonicalFlowTechniqueReference(
        technique_id=_as_str(mapping.get("technique_id")),
        technique_ref=_as_str(mapping.get("technique_ref")),
        technique_name=_as_str(mapping.get("technique_name")),
        confidence=confidence,
        provenance=[
            CanonicalFlowProvenanceRecord(
                source_label=_as_str(mapping.get("grounded_by")) or "ai_assisted_addition",
                source_kind=CanonicalFlowProvenanceKind.AI_ASSISTED_ADDITION,
                confidence=confidence,
            )
        ],
        evidence=[
            CanonicalFlowEvidenceRecord(
                source=_as_str(mapping.get("grounded_by")) or "attack-technique",
                excerpt=_as_str(mapping.get("technique_id"))
                or _as_str(mapping.get("technique_ref"))
                or _as_str(mapping.get("technique_name"))
                or "attack-technique",
                confidence=confidence,
            )
        ],
        conflicts=[],
    )


def _convert_evidence_record(item: Any) -> CanonicalFlowEvidenceRecord:
    mapping = _as_mapping(item)
    return CanonicalFlowEvidenceRecord(
        source=_as_str(mapping.get("source")) or "source",
        excerpt=_as_str(mapping.get("excerpt")) or "",
        citation=_as_str(mapping.get("citation")),
        source_object_id=_as_str(mapping.get("source_object_id")),
        source_field=_as_str(mapping.get("source_field")),
        confidence=_coerce_confidence(mapping.get("confidence"), default=None),
    )


def _convert_evidence_dict(item: Mapping[str, Any]) -> CanonicalFlowEvidenceRecord:
    return CanonicalFlowEvidenceRecord(
        source=_as_str(item.get("source")) or "source",
        excerpt=_as_str(item.get("excerpt")) or "",
        citation=_as_str(item.get("citation")),
        source_object_id=_as_str(item.get("source_object_id")),
        source_field=_as_str(item.get("source_field")),
        confidence=_coerce_confidence(item.get("confidence"), default=None),
    )


def _convert_fusion_provenance(item: FusionFindingProvenance) -> CanonicalFlowProvenanceRecord:
    return CanonicalFlowProvenanceRecord(
        source_label=item.source_label,
        source_kind=_map_fusion_provenance_kind(item.kind),
        source_object_id=item.source_object_id,
        source_field=item.source_field,
        confidence=item.confidence,
        notes=item.notes,
    )


def _convert_fact_origin(origin: FactOrigin) -> CanonicalFlowProvenanceRecord:
    return CanonicalFlowProvenanceRecord(
        source_label=origin.value,
        source_kind=CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT if origin == FactOrigin.DETERMINISTIC_SOURCE else CanonicalFlowProvenanceKind.AI_ASSISTED_ADDITION,
    )


def _build_attack_ref_evidence(ref: MergedAttackRef) -> CanonicalFlowEvidenceRecord:
    source = ref.external_source_name or ref.source_object_type or "attack-ref"
    excerpt = ref.source_field or ref.technique_id or ref.technique_ref or source
    return CanonicalFlowEvidenceRecord(
        source=source,
        excerpt=excerpt,
        citation=ref.external_url,
        source_object_id=ref.source_object_id,
        source_field=ref.source_field,
        confidence=ref.confidence,
    )


def _build_attack_ref_evidence_from_dict(ref: Mapping[str, Any]) -> CanonicalFlowEvidenceRecord:
    source = _as_str(ref.get("external_source_name")) or _as_str(ref.get("source_object_type")) or "attack-ref"
    excerpt = _as_str(ref.get("source_field")) or _as_str(ref.get("technique_id")) or _as_str(ref.get("technique_ref")) or source
    return CanonicalFlowEvidenceRecord(
        source=source,
        excerpt=excerpt,
        citation=_as_str(ref.get("external_url")),
        source_object_id=_as_str(ref.get("source_object_id")),
        source_field=_as_str(ref.get("source_field")),
        confidence=_coerce_confidence(ref.get("confidence"), default=1.0),
    )


def _map_fusion_provenance_kind(kind: FusionProvenanceKind) -> CanonicalFlowProvenanceKind:
    if kind == FusionProvenanceKind.DETERMINISTIC:
        return CanonicalFlowProvenanceKind.DETERMINISTIC_SOURCE_FACT
    return CanonicalFlowProvenanceKind.AI_ASSISTED_ADDITION


def _coerce_source_classification(value: Any) -> CanonicalFlowSourceClassification | None:
    if value is None:
        return None
    if isinstance(value, CanonicalFlowSourceClassification):
        return value
    if isinstance(value, SourceClassification):
        try:
            return CanonicalFlowSourceClassification(value.value)
        except ValueError:
            return CanonicalFlowSourceClassification.MIXED
    if isinstance(value, str):
        try:
            return CanonicalFlowSourceClassification(value)
        except ValueError:
            return CanonicalFlowSourceClassification.MIXED
    return CanonicalFlowSourceClassification.MIXED


def _coerce_confidence(value: Any, *, default: float | None) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return out


def _mapping_get(value: Any, key: str) -> Any:
    if hasattr(value, "get"):
        return value.get(key)
    return None


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
    if isinstance(value, Mapping):
        return value
    return {}
