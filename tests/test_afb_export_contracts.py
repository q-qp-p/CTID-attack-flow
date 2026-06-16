import json

from attack_flow_api.services.afb_export_contracts import (
    AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID,
    AFB_PINNED_TARGET_SCHEMA_FILENAME,
    AFB_PINNED_TARGET_SCHEMA_URI,
    AFB_PINNED_TARGET_VERSION,
    AfbExportAttackActionObject,
    AfbExportAttackAssetObject,
    AfbExportAttackFlowRootObject,
    AfbExportAttackConditionObject,
    AfbExportAttackOperatorObject,
    AfbExportExtensionDefinitionObject,
    AfbExportIdentityObject,
    AfbExportBundle,
    AfbExportBundleMetadata,
    AfbExportObjectCollection,
    AfbExportTargetMetadata,
    assemble_afb_export_bundle,
    build_afb_attack_action_object,
    build_afb_attack_asset_object,
    build_afb_attack_flow_root_object,
    build_afb_attack_condition_object,
    build_afb_attack_operator_object,
    build_afb_export_target_metadata,
    build_afb_export_bundle,
    validate_afb_export_bundle,
)
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowConditionNode,
    CanonicalFlowMetadata,
    CanonicalFlowOutput,
    CanonicalFlowTechniqueReference,
    CanonicalFlowOperatorNode,
)


def test_afb_export_target_metadata_defaults_are_pinned() -> None:
    target = build_afb_export_target_metadata()

    assert target.target_name == "Attack Flow"
    assert target.target_version == AFB_PINNED_TARGET_VERSION
    assert target.schema_filename == AFB_PINNED_TARGET_SCHEMA_FILENAME
    assert target.schema_uri == AFB_PINNED_TARGET_SCHEMA_URI
    assert target.extension_definition_id == AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID
    assert target.extension_types == ["new-sdo"]


def test_afb_export_bundle_defaults_to_empty_object_collection() -> None:
    bundle = build_afb_export_bundle("bundle--afb-1")

    assert isinstance(bundle, AfbExportBundle)
    assert isinstance(bundle.metadata, AfbExportBundleMetadata)
    assert isinstance(bundle.objects, AfbExportObjectCollection)
    assert isinstance(bundle.metadata.target, AfbExportTargetMetadata)
    assert bundle.metadata.bundle_id == "bundle--afb-1"
    assert bundle.metadata.object_count == 0
    assert bundle.objects.objects == []
    assert bundle.to_json_ready() == {
        "type": "bundle",
        "id": "bundle--afb-1",
        "schema_version": "afb-v2-export-contracts",
        "objects": [],
    }


def test_build_afb_export_bundle_metadata_preserves_context_lists() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--bundle-1",
            name="Example flow",
            scope="incident",
            authors=["analyst-a", "analyst-a", "analyst-b"],
            external_references=["https://example.com/a", "https://example.com/a", "https://example.com/b"],
            start_refs=[],
        ),
        nodes=[
            CanonicalFlowAssetNode(
                id="attack-asset--1",
                name="Host asset",
                object_ref="malware--1",
            ),
            CanonicalFlowAssetNode(
                id="attack-asset--2",
                name="Process asset",
                object_ref="malware--1",
            ),
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    bundle = build_afb_export_bundle("bundle--afb-ctx", canonical_flow=canonical, object_count=0)

    assert bundle.metadata.authors == ["analyst-a", "analyst-b"]
    assert bundle.metadata.external_references == ["https://example.com/a", "https://example.com/b"]
    assert bundle.metadata.supporting_object_refs == ["malware--1"]


def test_build_afb_attack_flow_root_object_maps_canonical_metadata() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--root-1",
            name="Example flow",
            scope="incident",
            description="  Example flow description.  ",
            external_references=["https://example.com/report"],
            start_refs=["attack-action--1", "", "attack-action--1"],
        ),
        nodes=[],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    root = build_afb_attack_flow_root_object(canonical)

    assert isinstance(root, AfbExportAttackFlowRootObject)
    assert root.type == "attack-flow"
    assert root.spec_version == "2.1"
    assert root.id == "attack-flow--root-1"
    assert root.name == "Example flow"
    assert root.description == "Example flow description."
    assert root.scope == "incident"
    assert root.start_refs == ["attack-action--1"]
    assert root.external_references == [
        {"source_name": "https://example.com/report", "url": "https://example.com/report"}
    ]
    assert root.extensions == {
        AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}
    }


def test_build_afb_attack_action_object_preserves_explicit_mapping_fields() -> None:
    node = CanonicalFlowActionNode(
        id="attack-action--1",
        name="Observed step",
        description="  Observed command exactly as reported.  ",
        technique=CanonicalFlowTechniqueReference(
            technique_id="T1059",
            technique_ref="attack-pattern--1",
            source_object_id="attack-pattern--1",
        ),
        tactic_ref="x-mitre-tactic--1",
        asset_refs=["attack-asset--1"],
        effect_refs=["attack-condition--1"],
    )

    action = build_afb_attack_action_object(node)

    assert isinstance(action, AfbExportAttackActionObject)
    assert action.type == "attack-action"
    assert action.spec_version == "2.1"
    assert action.id == "attack-action--1"
    assert action.name == "Observed step"
    assert action.description == "  Observed command exactly as reported.  "
    assert action.technique_id == "T1059"
    assert action.technique_ref == "attack-pattern--1"
    assert action.tactic_id is None
    assert action.tactic_ref == "x-mitre-tactic--1"
    assert action.asset_refs == ["attack-asset--1"]
    assert action.effect_refs == ["attack-condition--1"]
    assert action.execution_start is None
    assert action.execution_end is None
    assert action.extensions == {
        AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}
    }


def test_build_afb_attack_action_object_allows_unmapped_actions() -> None:
    node = CanonicalFlowActionNode(
        id="attack-action--2",
        name="Unmapped step",
        description="Observed command exactly as reported.",
        asset_refs=[],
        effect_refs=[],
    )

    action = build_afb_attack_action_object(node)

    assert action.technique_id is None
    assert action.technique_ref is None
    assert action.tactic_id is None
    assert action.tactic_ref is None
    assert action.description == "Observed command exactly as reported."


def test_build_afb_attack_action_object_preserves_explicit_technique_ref_without_inference() -> None:
    node = CanonicalFlowActionNode(
        id="attack-action--3",
        name="Technique-ref only",
        description="Observed command exactly as reported.",
        technique=CanonicalFlowTechniqueReference(
            technique_ref="attack-pattern--explicit",
            source_object_id="attack-pattern--explicit",
        ),
    )

    action = build_afb_attack_action_object(node)

    assert action.technique_id is None
    assert action.technique_ref == "attack-pattern--explicit"
    assert action.description == "Observed command exactly as reported."


def test_build_afb_attack_condition_object_preserves_boolean_branching() -> None:
    node = CanonicalFlowConditionNode(
        id="attack-condition--1",
        description="Observed branch decision exactly as reported.",
        condition_value="true",
        on_true_refs=["attack-operator--1", "attack-action--2"],
        on_false_refs=["attack-action--3"],
    )

    condition = build_afb_attack_condition_object(node)

    assert isinstance(condition, AfbExportAttackConditionObject)
    assert condition.type == "attack-condition"
    assert condition.spec_version == "2.1"
    assert condition.id == "attack-condition--1"
    assert condition.description == "Observed branch decision exactly as reported."
    assert condition.on_true_refs == ["attack-operator--1", "attack-action--2"]
    assert condition.on_false_refs == ["attack-action--3"]
    assert condition.extensions == {
        AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}
    }


def test_build_afb_attack_operator_object_preserves_boolean_operator() -> None:
    node = CanonicalFlowOperatorNode(
        id="attack-operator--1",
        operator="AND",
        effect_refs=["attack-action--1", "attack-action--2"],
    )

    operator = build_afb_attack_operator_object(node)

    assert isinstance(operator, AfbExportAttackOperatorObject)
    assert operator.type == "attack-operator"
    assert operator.spec_version == "2.1"
    assert operator.id == "attack-operator--1"
    assert operator.operator == "AND"
    assert operator.effect_refs == ["attack-action--1", "attack-action--2"]
    assert operator.extensions == {
        AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}
    }


def test_build_afb_attack_asset_object_preserves_object_ref_context() -> None:
    node = CanonicalFlowAssetNode(
        id="attack-asset--1",
        name="Host asset",
        description="Observed asset context exactly as reported.",
        object_ref="malware--1",
    )

    asset = build_afb_attack_asset_object(node)

    assert isinstance(asset, AfbExportAttackAssetObject)
    assert asset.type == "attack-asset"
    assert asset.spec_version == "2.1"
    assert asset.id == "attack-asset--1"
    assert asset.name == "Host asset"
    assert asset.description == "Observed asset context exactly as reported."
    assert asset.object_ref == "malware--1"
    assert asset.extensions == {
        AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}
    }


def test_build_afb_attack_asset_object_omits_blank_object_ref() -> None:
    node = CanonicalFlowAssetNode(
        id="attack-asset--2",
        name="Unlinked asset",
        object_ref="   ",
    )

    asset = build_afb_attack_asset_object(node)

    assert asset.object_ref is None


def test_validate_afb_export_bundle_reports_target_and_count_mismatches() -> None:
    bundle = AfbExportBundle(
        metadata=AfbExportBundleMetadata(
            bundle_id="bundle--afb-2",
            object_count=0,
            target=AfbExportTargetMetadata(target_version="9.9.9"),
        ),
        objects=AfbExportObjectCollection(
            objects=[{"type": "attack-flow", "id": "attack-flow--afb-2"}]
        ),
    )

    result = validate_afb_export_bundle(bundle)

    assert result.valid is False
    assert result.bundle_id == "bundle--afb-2"
    assert result.object_count == 1
    assert any(error.code == "target_version_invalid" for error in result.errors)
    assert any(error.code == "object_count_mismatch" for error in result.errors)


def test_assemble_afb_export_bundle_builds_pinned_target_artifact() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--assemble-1",
            name="Example flow",
            scope="incident",
            authors=["analyst-a"],
            external_references=["https://example.com/report"],
            start_refs=["attack-action--1"],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--1",
                name="Observed step",
                description="Observed command exactly as reported.",
                asset_refs=["attack-asset--1"],
            ),
            CanonicalFlowAssetNode(
                id="attack-asset--1",
                name="Host asset",
                object_ref="malware--1",
            ),
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    bundle = assemble_afb_export_bundle(canonical)
    export_json = bundle.to_export_json_ready()

    assert bundle.validation_errors == []
    assert bundle.metadata.object_count == 5
    assert export_json["type"] == "bundle"
    assert export_json["id"].startswith("bundle--")
    assert [item["type"] for item in export_json["objects"][:3]] == ["extension-definition", "identity", "attack-flow"]
    assert json.loads(bundle.to_export_json_bytes().decode("utf-8")) == export_json


def test_assemble_afb_export_bundle_builds_builder_diagram_export() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--diagram-1",
            name="Example flow",
            scope="incident",
            start_refs=["attack-action--1"],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--1",
                name="Observed step",
                description="Observed command exactly as reported.",
                asset_refs=["attack-asset--1"],
            ),
            CanonicalFlowAssetNode(
                id="attack-asset--1",
                name="Host asset",
                object_ref="malware--1",
            ),
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    bundle = assemble_afb_export_bundle(canonical)
    diagram_export = bundle.to_diagram_export_ready()

    assert diagram_export["schema"] == "attack_flow_v2"
    assert [item["id"] for item in diagram_export["objects"][:3]] == ["flow", "action", "asset"]
    assert diagram_export["objects"][0]["objects"] == ["attack-action--1", "attack-asset--1"]
    assert diagram_export["objects"][1]["anchors"] == {}
    assert diagram_export["objects"][1]["properties"][0] == ["name", "Observed step"]
    assert json.loads(bundle.to_diagram_export_bytes().decode("utf-8")) == diagram_export


def test_assemble_afb_export_bundle_prunes_invalid_internal_refs_and_reports_errors() -> None:
    canonical = CanonicalFlowOutput(
        metadata=CanonicalFlowMetadata(
            flow_id="attack-flow--assemble-2",
            name="Example flow",
            scope="incident",
            start_refs=["attack-action--missing"],
        ),
        nodes=[
            CanonicalFlowActionNode(
                id="attack-action--1",
                name="Observed step",
                description="Observed command exactly as reported.",
                asset_refs=["attack-asset--missing"],
                effect_refs=["attack-condition--missing"],
            )
        ],
        edges=[],
        provenance={},
        conflicts=[],
        validation_errors=[],
    )

    bundle = assemble_afb_export_bundle(canonical)
    export_json = bundle.to_export_json_ready()
    root = next(item for item in export_json["objects"] if item["type"] == "attack-flow")

    assert root["start_refs"] == []
    assert any(error.code == "attack_flow_start_ref_invalid" for error in bundle.validation_errors)
    assert any(error.code == "attack_action_asset_ref_invalid" for error in bundle.validation_errors)
    assert any(error.code == "attack_action_effect_ref_invalid" for error in bundle.validation_errors)
