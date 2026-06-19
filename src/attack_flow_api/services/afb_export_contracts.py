from typing import Any, Literal
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field

from attack_flow.schema import ATTACK_FLOW_EXTENSION_ID
from attack_flow_api.services.canonical_flow_contracts import (
    CanonicalFlowActionNode,
    CanonicalFlowAssetNode,
    CanonicalFlowConditionNode,
    CanonicalFlowOperatorNode,
    CanonicalFlowOutput,
)


AFB_PINNED_TARGET_NAME = "Attack Flow"
AFB_PINNED_TARGET_VERSION = "2.0.0"
AFB_PINNED_TARGET_SCHEMA_FILENAME = "attack-flow-schema-2.0.0.json"
AFB_PINNED_TARGET_SCHEMA_URI = f"./{AFB_PINNED_TARGET_SCHEMA_FILENAME}"
AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID = ATTACK_FLOW_EXTENSION_ID
AFB_PINNED_TARGET_EXTENSION_TYPES = ["new-sdo"]
AFB_PINNED_TARGET_EXTENSION_SCHEMA_URL = (
    "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json"
)
AFB_PINNED_TARGET_EXTENSION_CREATED = "2022-08-02T19:34:35.143Z"
AFB_PINNED_TARGET_EXTENSION_MODIFIED = "2022-08-02T19:34:35.143Z"
AFB_PINNED_TARGET_EXTENSION_CREATED_BY_REF = "identity--d673f8cb-c168-42da-8ed4-0cb26725f86c"
AFB_PINNED_TARGET_IDENTITY_ID = AFB_PINNED_TARGET_EXTENSION_CREATED_BY_REF
AFB_PINNED_TARGET_IDENTITY_NAME = "MITRE Center for Threat-Informed Defense"
AFB_PINNED_TARGET_IDENTITY_CLASS = "organization"


class AfbExportCompatibilityError(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    object_ref: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class AfbExportTargetMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_name: str = Field(default=AFB_PINNED_TARGET_NAME, min_length=1)
    target_version: str = Field(default=AFB_PINNED_TARGET_VERSION, min_length=1)
    schema_filename: str = Field(default=AFB_PINNED_TARGET_SCHEMA_FILENAME, min_length=1)
    schema_uri: str = Field(default=AFB_PINNED_TARGET_SCHEMA_URI, min_length=1)
    extension_definition_id: str = Field(default=AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID, min_length=1)
    extension_types: list[str] = Field(default_factory=lambda: list(AFB_PINNED_TARGET_EXTENSION_TYPES))


class AfbExportObjectCollection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objects: list[dict[str, Any]] = Field(default_factory=list)


class AfbExportAttackFlowRootObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-flow"] = "attack-flow"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str | None = None
    scope: str = Field(min_length=1)
    start_refs: list[str] = Field(default_factory=list)
    external_references: list[dict[str, Any]] = Field(default_factory=list)
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class AfbExportAttackActionObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-action"] = "attack-action"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    technique_id: str | None = None
    technique_ref: str | None = None
    technique_name: str | None = None
    technique_description: str | None = None
    technique_aliases: list[str] = Field(default_factory=list)
    technique_kill_chain_phases: list[str] = Field(default_factory=list)
    technique_tags: list[str] = Field(default_factory=list)
    tactic_id: str | None = None
    tactic_ref: str | None = None
    asset_refs: list[str] = Field(default_factory=list)
    effect_refs: list[str] = Field(default_factory=list)
    execution_start: str | None = None
    execution_end: str | None = None
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class AfbExportAttackConditionObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-condition"] = "attack-condition"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    description: str | None = None
    on_true_refs: list[str] = Field(default_factory=list)
    on_false_refs: list[str] = Field(default_factory=list)
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class AfbExportAttackOperatorObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-operator"] = "attack-operator"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    operator: Literal["AND", "OR"]
    effect_refs: list[str] = Field(default_factory=list)
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class AfbExportAttackAssetObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["attack-asset"] = "attack-asset"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str | None = None
    tags: dict[str, bool] | None = None
    object_ref: str | None = None
    extensions: dict[str, dict[str, str]] = Field(default_factory=dict)


class AfbExportExtensionDefinitionObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["extension-definition"] = "extension-definition"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(default=AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID, min_length=1)
    name: str = Field(default=AFB_PINNED_TARGET_NAME, min_length=1)
    description: str = Field(default="Extends STIX 2.1 with features to create Attack Flows.", min_length=1)
    created: str = Field(default=AFB_PINNED_TARGET_EXTENSION_CREATED, min_length=1)
    modified: str = Field(default=AFB_PINNED_TARGET_EXTENSION_MODIFIED, min_length=1)
    created_by_ref: str = Field(default=AFB_PINNED_TARGET_EXTENSION_CREATED_BY_REF, min_length=1)
    schema_uri: str = Field(
        default=AFB_PINNED_TARGET_EXTENSION_SCHEMA_URL,
        min_length=1,
        alias="schema",
        serialization_alias="schema",
    )
    version: str = Field(default=AFB_PINNED_TARGET_VERSION, min_length=1)
    extension_types: list[str] = Field(default_factory=lambda: list(AFB_PINNED_TARGET_EXTENSION_TYPES))
    external_references: list[dict[str, Any]] = Field(default_factory=list)


class AfbExportIdentityObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["identity"] = "identity"
    spec_version: Literal["2.1"] = "2.1"
    id: str = Field(default=AFB_PINNED_TARGET_IDENTITY_ID, min_length=1)
    created_by_ref: str = Field(default=AFB_PINNED_TARGET_IDENTITY_ID, min_length=1)
    created: str = Field(default=AFB_PINNED_TARGET_EXTENSION_CREATED, min_length=1)
    modified: str = Field(default=AFB_PINNED_TARGET_EXTENSION_MODIFIED, min_length=1)
    name: str = Field(default=AFB_PINNED_TARGET_IDENTITY_NAME, min_length=1)
    identity_class: Literal["organization"] = AFB_PINNED_TARGET_IDENTITY_CLASS


class AfbExportBundleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="afb-v2-export-contracts", min_length=1)
    target: AfbExportTargetMetadata = Field(default_factory=AfbExportTargetMetadata)
    bundle_id: str = Field(min_length=1)
    object_count: int = Field(default=0, ge=0)
    authors: list[str] = Field(default_factory=list)
    external_references: list[str] = Field(default_factory=list)
    supporting_object_refs: list[str] = Field(default_factory=list)


class AfbExportCompatibilityResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    bundle_id: str
    object_count: int
    target: AfbExportTargetMetadata
    errors: list[AfbExportCompatibilityError] = Field(default_factory=list)


class AfbExportArtifactMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="afb-v2-export-artifact", min_length=1)
    validation_state: str = Field(default="pending", min_length=1)
    bundle_id: str | None = None
    object_count: int | None = None
    exported_at: str | None = None
    export_status: str = Field(default="pending", min_length=1)
    error_code: str | None = None
    error_message: str | None = None
    validation_errors: list[dict[str, Any]] = Field(default_factory=list)


class AfbExportBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    metadata: AfbExportBundleMetadata
    objects: AfbExportObjectCollection = Field(default_factory=AfbExportObjectCollection)
    validation_errors: list[AfbExportCompatibilityError] = Field(default_factory=list)
    canonical_flow: CanonicalFlowOutput | None = Field(default=None, exclude=True)

    def to_json_ready(self) -> dict[str, Any]:
        return self._build_bundle_json_ready(include_schema_version=True)

    def to_json_bytes(self) -> bytes:
        import json

        return json.dumps(self.to_json_ready(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_export_json_ready(self) -> dict[str, Any]:
        return self._build_bundle_json_ready(include_schema_version=False)

    def to_export_json_bytes(self) -> bytes:
        import json

        return json.dumps(self.to_export_json_ready(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_diagram_export_ready(self) -> dict[str, Any]:
        return _build_diagram_export_json_ready(self)

    def to_diagram_export_bytes(self) -> bytes:
        import json

        return json.dumps(self.to_diagram_export_ready(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _build_bundle_json_ready(self, *, include_schema_version: bool) -> dict[str, Any]:
        payload = {
            "type": "bundle",
            "id": self.metadata.bundle_id,
            "objects": list(self.objects.objects),
        }
        if include_schema_version:
            payload["schema_version"] = self.metadata.schema_version
        return payload


def build_afb_export_target_metadata() -> AfbExportTargetMetadata:
    return AfbExportTargetMetadata()


def build_afb_export_bundle_metadata(
    bundle_id: str,
    *,
    object_count: int = 0,
    canonical_flow: CanonicalFlowOutput | None = None,
    target: AfbExportTargetMetadata | None = None,
) -> AfbExportBundleMetadata:
    authors: list[str] = []
    external_references: list[str] = []
    supporting_object_refs: list[str] = []
    if canonical_flow is not None:
        authors = _dedupe_preserve_order(_coerce_string_list(canonical_flow.metadata.authors))
        external_references = _dedupe_preserve_order(_coerce_string_list(canonical_flow.metadata.external_references))
        supporting_object_refs = _build_supporting_object_refs(canonical_flow)
    return AfbExportBundleMetadata(
        bundle_id=bundle_id,
        object_count=object_count,
        target=target or build_afb_export_target_metadata(),
        authors=authors,
        external_references=external_references,
        supporting_object_refs=supporting_object_refs,
    )


def build_afb_export_bundle(
    bundle_id: str,
    *,
    object_count: int = 0,
    canonical_flow: CanonicalFlowOutput | None = None,
    target: AfbExportTargetMetadata | None = None,
) -> AfbExportBundle:
    return AfbExportBundle(
        metadata=build_afb_export_bundle_metadata(
            bundle_id,
            object_count=object_count,
            canonical_flow=canonical_flow,
            target=target,
        ),
        canonical_flow=canonical_flow,
    )


def assemble_afb_export_bundle(canonical_flow: CanonicalFlowOutput) -> AfbExportBundle:
    bundle = build_afb_export_bundle(
        _build_deterministic_bundle_id(canonical_flow.metadata.flow_id),
        canonical_flow=canonical_flow,
    )
    export_objects = _build_export_object_models(canonical_flow)
    prune_errors = _prune_invalid_export_references(export_objects)
    bundle.objects.objects = [obj.model_dump(mode="json", by_alias=True) for obj in export_objects]
    bundle.metadata.object_count = len(bundle.objects.objects)

    validation = validate_afb_export_bundle(bundle)
    bundle.validation_errors = prune_errors + list(validation.errors)
    return bundle


def build_afb_attack_flow_root_object(canonical_flow: CanonicalFlowOutput) -> AfbExportAttackFlowRootObject:
    metadata = canonical_flow.metadata
    return AfbExportAttackFlowRootObject(
        id=metadata.flow_id,
        name=metadata.name,
        description=_coerce_non_empty_description(metadata.description),
        scope=metadata.scope,
        start_refs=_dedupe_preserve_order(_coerce_string_list(metadata.start_refs)),
        external_references=_build_external_reference_objects(metadata.external_references),
        extensions={AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}},
    )


def build_afb_attack_action_object(node: CanonicalFlowActionNode) -> AfbExportAttackActionObject:
    technique = node.technique
    return AfbExportAttackActionObject(
        id=node.id,
        name=node.name or node.id,
        description=_coerce_verbatim_description(node.description),
        confidence=node.confidence,
        technique_id=_coerce_non_empty_string(getattr(technique, "technique_id", None)),
        technique_ref=_coerce_non_empty_string(getattr(technique, "technique_ref", None)),
        technique_name=_coerce_non_empty_string(getattr(technique, "technique_name", None)),
        technique_description=_coerce_verbatim_description(getattr(technique, "description", None)),
        technique_aliases=_coerce_string_list(getattr(technique, "aliases", None)),
        technique_kill_chain_phases=_coerce_string_list(getattr(technique, "kill_chain_phases", None)),
        technique_tags=_coerce_string_list(getattr(technique, "tags", None)),
        tactic_id=_coerce_non_empty_string(getattr(node, "tactic_id", None)),
        tactic_ref=_coerce_non_empty_string(getattr(node, "tactic_ref", None)),
        asset_refs=_coerce_string_list(getattr(node, "asset_refs", None)),
        effect_refs=_coerce_string_list(getattr(node, "effect_refs", None)),
        extensions={AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}},
    )


def build_afb_attack_condition_object(node: CanonicalFlowConditionNode) -> AfbExportAttackConditionObject:
    return AfbExportAttackConditionObject(
        id=node.id,
        description=_coerce_verbatim_description(node.description),
        on_true_refs=_dedupe_preserve_order(_coerce_string_list(getattr(node, "on_true_refs", None))),
        on_false_refs=_dedupe_preserve_order(_coerce_string_list(getattr(node, "on_false_refs", None))),
        extensions={AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}},
    )


def build_afb_attack_operator_object(node: CanonicalFlowOperatorNode) -> AfbExportAttackOperatorObject:
    operator = _coerce_non_empty_string(getattr(node, "operator", None))
    if operator not in {"AND", "OR"}:
        raise ValueError(f"unsupported attack-operator value: {operator!r}")
    return AfbExportAttackOperatorObject(
        id=node.id,
        operator=operator,
        effect_refs=_dedupe_preserve_order(_coerce_string_list(getattr(node, "effect_refs", None))),
        extensions={AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}},
    )


def build_afb_attack_asset_object(node: CanonicalFlowAssetNode) -> AfbExportAttackAssetObject:
    return AfbExportAttackAssetObject(
        id=node.id,
        name=node.name or node.id,
        description=_coerce_verbatim_description(node.description),
        tags=_build_tags_property(node.tags),
        object_ref=_coerce_non_empty_string(getattr(node, "object_ref", None)),
        extensions={AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID: {"extension_type": "new-sdo"}},
    )


def build_afb_extension_definition_object() -> AfbExportExtensionDefinitionObject:
    return AfbExportExtensionDefinitionObject(
        external_references=[
            {
                "source_name": "Documentation",
                "description": "Documentation for Attack Flow",
                "url": "https://center-for-threat-informed-defense.github.io/attack-flow",
            },
            {
                "source_name": "GitHub",
                "description": "Source code repository for Attack Flow",
                "url": "https://github.com/center-for-threat-informed-defense/attack-flow",
            },
        ]
    )


def build_afb_identity_object() -> AfbExportIdentityObject:
    return AfbExportIdentityObject()


def _build_export_object_models(canonical_flow: CanonicalFlowOutput) -> list[BaseModel]:
    return [
        build_afb_extension_definition_object(),
        build_afb_identity_object(),
        build_afb_attack_flow_root_object(canonical_flow),
        *build_attack_action_objects(canonical_flow),
        *build_attack_condition_objects(canonical_flow),
        *build_attack_operator_objects(canonical_flow),
        *build_attack_asset_objects(canonical_flow),
    ]


def _prune_invalid_export_references(export_objects: list[BaseModel]) -> list[AfbExportCompatibilityError]:
    errors: list[AfbExportCompatibilityError] = []
    object_index = {getattr(obj, "id"): obj for obj in export_objects if getattr(obj, "id", None)}
    allowed_effect_targets = set(object_index)
    allowed_start_targets = {
        object_id
        for object_id, obj in object_index.items()
        if isinstance(obj, (AfbExportAttackActionObject, AfbExportAttackConditionObject))
    }
    allowed_asset_targets = {object_id for object_id, obj in object_index.items() if isinstance(obj, AfbExportAttackAssetObject)}

    root = next((obj for obj in export_objects if isinstance(obj, AfbExportAttackFlowRootObject)), None)
    if root is not None:
        root.start_refs = _filter_refs_with_error(
            root.start_refs,
            allowed_start_targets,
            errors,
            code="attack_flow_start_ref_invalid",
            message_prefix="attack-flow start_ref does not target an exported object",
        )

    for obj in export_objects:
        if isinstance(obj, AfbExportAttackActionObject):
            obj.asset_refs = _filter_refs_with_error(
                obj.asset_refs,
                allowed_asset_targets,
                errors,
                code="attack_action_asset_ref_invalid",
                message_prefix="attack-action asset_ref does not target an exported attack-asset",
                object_ref=obj.id,
                details_key="target_ref",
            )
            obj.effect_refs = _filter_refs_with_error(
                obj.effect_refs,
                allowed_effect_targets,
                errors,
                code="attack_action_effect_ref_invalid",
                message_prefix="attack-action effect_ref does not target an exported object",
                object_ref=obj.id,
                details_key="target_ref",
            )
        elif isinstance(obj, AfbExportAttackConditionObject):
            obj.on_true_refs = _filter_refs_with_error(
                obj.on_true_refs,
                allowed_effect_targets,
                errors,
                code="attack_condition_ref_invalid",
                message_prefix="attack-condition on_true_refs does not target an exported object",
                object_ref=obj.id,
                details_key="target_ref",
                details_extra={"field": "on_true_refs"},
            )
            obj.on_false_refs = _filter_refs_with_error(
                obj.on_false_refs,
                allowed_effect_targets,
                errors,
                code="attack_condition_ref_invalid",
                message_prefix="attack-condition on_false_refs does not target an exported object",
                object_ref=obj.id,
                details_key="target_ref",
                details_extra={"field": "on_false_refs"},
            )
        elif isinstance(obj, AfbExportAttackOperatorObject):
            obj.effect_refs = _filter_refs_with_error(
                obj.effect_refs,
                allowed_effect_targets,
                errors,
                code="attack_operator_ref_invalid",
                message_prefix="attack-operator effect_ref does not target an exported object",
                object_ref=obj.id,
                details_key="target_ref",
            )

    return errors


def _filter_refs_with_error(
    refs: list[str],
    allowed_targets: set[str],
    errors: list[AfbExportCompatibilityError],
    *,
    code: str,
    message_prefix: str,
    object_ref: str | None = None,
    details_key: str | None = None,
    details_extra: dict[str, Any] | None = None,
) -> list[str]:
    filtered: list[str] = []
    for ref in _dedupe_preserve_order(_coerce_string_list(refs)):
        if ref in allowed_targets:
            filtered.append(ref)
            continue
        details = dict(details_extra or {})
        if details_key is not None:
            details[details_key] = ref
        errors.append(_compatibility_error(code, f"{message_prefix}: {ref}", object_ref=object_ref or ref, details=details))
    return filtered


def build_attack_action_objects(canonical_flow: CanonicalFlowOutput) -> list[AfbExportAttackActionObject]:
    action_nodes = [node for node in canonical_flow.nodes if isinstance(node, CanonicalFlowActionNode)]
    return [build_afb_attack_action_object(node) for node in action_nodes]


def build_attack_condition_objects(canonical_flow: CanonicalFlowOutput) -> list[AfbExportAttackConditionObject]:
    condition_nodes = [node for node in canonical_flow.nodes if isinstance(node, CanonicalFlowConditionNode)]
    return [build_afb_attack_condition_object(node) for node in condition_nodes]


def build_attack_operator_objects(canonical_flow: CanonicalFlowOutput) -> list[AfbExportAttackOperatorObject]:
    operator_nodes = [node for node in canonical_flow.nodes if isinstance(node, CanonicalFlowOperatorNode)]
    return [build_afb_attack_operator_object(node) for node in operator_nodes]


def build_attack_asset_objects(canonical_flow: CanonicalFlowOutput) -> list[AfbExportAttackAssetObject]:
    asset_nodes = [node for node in canonical_flow.nodes if isinstance(node, CanonicalFlowAssetNode)]
    return [build_afb_attack_asset_object(node) for node in asset_nodes]


def _build_deterministic_bundle_id(flow_id: str) -> str:
    import uuid

    return f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, f'attack-flow-export:{flow_id}')}"


def validate_afb_export_bundle(bundle: AfbExportBundle) -> AfbExportCompatibilityResult:
    errors: list[AfbExportCompatibilityError] = []
    export_json = bundle.to_export_json_ready()

    _validate_top_level_export_fields(export_json, errors)
    _validate_target_metadata(bundle.metadata.target, errors)
    object_index = _validate_object_collection(bundle.objects, bundle.metadata.supporting_object_refs, errors)
    _validate_object_count(bundle, errors)
    _validate_pinned_structure(object_index, bundle, errors)

    return AfbExportCompatibilityResult(
        valid=not errors,
        bundle_id=bundle.metadata.bundle_id,
        object_count=len(bundle.objects.objects),
        target=bundle.metadata.target,
        errors=errors,
    )


def _validate_target_metadata(
    target: AfbExportTargetMetadata,
    errors: list[AfbExportCompatibilityError],
) -> None:
    if target.target_name != AFB_PINNED_TARGET_NAME:
        errors.append(_compatibility_error("target_name_invalid", f"target name must be {AFB_PINNED_TARGET_NAME!r}"))
    if target.target_version != AFB_PINNED_TARGET_VERSION:
        errors.append(_compatibility_error("target_version_invalid", f"target version must be {AFB_PINNED_TARGET_VERSION!r}"))
    if target.schema_filename != AFB_PINNED_TARGET_SCHEMA_FILENAME:
        errors.append(_compatibility_error("schema_filename_invalid", f"schema filename must be {AFB_PINNED_TARGET_SCHEMA_FILENAME!r}"))
    if target.schema_uri != AFB_PINNED_TARGET_SCHEMA_URI:
        errors.append(_compatibility_error("schema_uri_invalid", f"schema uri must be {AFB_PINNED_TARGET_SCHEMA_URI!r}"))
    if target.extension_definition_id != AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID:
        errors.append(_compatibility_error("extension_definition_id_invalid", "extension definition id must match the pinned Attack Flow extension"))
    if target.extension_types != AFB_PINNED_TARGET_EXTENSION_TYPES:
        errors.append(_compatibility_error("extension_types_invalid", "extension types must be ['new-sdo']"))


def _validate_top_level_export_fields(
    export_json: dict[str, Any],
    errors: list[AfbExportCompatibilityError],
) -> None:
    if export_json.get("type") != "bundle":
        errors.append(_compatibility_error("bundle_type_invalid", "bundle type must be 'bundle'"))
    if not _coerce_non_empty_string(export_json.get("id")) or not _coerce_non_empty_string(export_json.get("id")).startswith("bundle--"):
        errors.append(_compatibility_error("bundle_id_invalid", "bundle id must start with 'bundle--'"))
    if not isinstance(export_json.get("objects"), list):
        errors.append(_compatibility_error("bundle_objects_invalid", "bundle objects must be a list"))
    elif not export_json.get("objects"):
        errors.append(_compatibility_error("bundle_objects_empty", "bundle must contain exported objects"))


def _validate_object_collection(
    objects: AfbExportObjectCollection,
    supporting_object_refs: list[str],
    errors: list[AfbExportCompatibilityError],
) -> dict[str, dict[str, Any]]:
    object_index: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    for item in objects.objects:
        if not isinstance(item, dict):
            errors.append(_compatibility_error("object_invalid", "exported objects must be JSON objects"))
            continue

        object_type = _coerce_non_empty_string(item.get("type"))
        object_id = _coerce_non_empty_string(item.get("id"))
        if object_type is None or object_id is None:
            errors.append(_compatibility_error("object_missing_fields", "exported objects require type and id", object_ref=object_id))
            continue

        if object_id in seen_ids:
            errors.append(_compatibility_error("object_duplicate_id", f"duplicate exported object id: {object_id}", object_ref=object_id))
            continue
        seen_ids.add(object_id)
        object_index[object_id] = item

        if object_type == "extension-definition":
            _validate_extension_definition_object(item, errors)
        elif object_type == "identity":
            _validate_identity_object(item, errors)
        elif object_type == "attack-flow":
            _validate_attack_flow_object(item, errors)
        elif object_type == "attack-action":
            _validate_attack_action_object(item, errors)
        elif object_type == "attack-condition":
            _validate_attack_condition_object(item, errors)
        elif object_type == "attack-operator":
            _validate_attack_operator_object(item, errors)
        elif object_type == "attack-asset":
            _validate_attack_asset_object(item, supporting_object_refs, errors)
        else:
            errors.append(_compatibility_error("object_type_unsupported", f"unsupported exported object type: {object_type}", object_ref=object_id))

    return object_index


def _validate_object_count(bundle: AfbExportBundle, errors: list[AfbExportCompatibilityError]) -> None:
    if bundle.metadata.object_count != len(bundle.objects.objects):
        errors.append(
            _compatibility_error(
                "object_count_mismatch",
                "object_count must match the number of exported objects",
                details={"declared": bundle.metadata.object_count, "actual": len(bundle.objects.objects)},
            )
        )


def _validate_pinned_structure(
    object_index: dict[str, dict[str, Any]],
    bundle: AfbExportBundle,
    errors: list[AfbExportCompatibilityError],
) -> None:
    extension_definition = next((item for item in object_index.values() if item.get("type") == "extension-definition"), None)
    identity = next((item for item in object_index.values() if item.get("type") == "identity"), None)
    flow = next((item for item in object_index.values() if item.get("type") == "attack-flow"), None)

    if extension_definition is None:
        errors.append(_compatibility_error("extension_definition_missing", "bundle must contain the pinned extension-definition object"))
    elif _coerce_non_empty_string(extension_definition.get("id")) != AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID:
        errors.append(_compatibility_error("extension_definition_id_invalid", "extension definition id must match the pinned Attack Flow extension"))

    if identity is None:
        errors.append(_compatibility_error("identity_missing", "bundle must contain the pinned Attack Flow identity object"))
    elif _coerce_non_empty_string(identity.get("id")) != AFB_PINNED_TARGET_IDENTITY_ID:
        errors.append(_compatibility_error("identity_id_invalid", "identity id must match the pinned Attack Flow identity"))

    if flow is None:
        errors.append(_compatibility_error("attack_flow_missing", "bundle must contain exactly one attack-flow object"))
        return

    for field_name in ("id", "name", "scope", "start_refs"):
        if field_name not in flow:
            errors.append(_compatibility_error("attack_flow_field_missing", f"attack-flow object missing required field: {field_name}", object_ref=_coerce_non_empty_string(flow.get("id"))))

    extensions = flow.get("extensions")
    if not isinstance(extensions, dict) or AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID not in extensions:
        errors.append(_compatibility_error("attack_flow_extension_missing", "attack-flow object must include the Attack Flow extension reference", object_ref=_coerce_non_empty_string(flow.get("id"))))

    start_refs = _coerce_string_list(flow.get("start_refs"))
    for ref in start_refs:
        if ref not in object_index:
            errors.append(_compatibility_error("attack_flow_start_ref_invalid", f"attack-flow start_ref does not target an exported object: {ref}", object_ref=ref))
            continue
        if object_index[ref].get("type") not in {"attack-action", "attack-condition"}:
            errors.append(_compatibility_error("attack_flow_start_ref_type_invalid", f"attack-flow start_ref must target an attack-action or attack-condition: {ref}", object_ref=ref))


def _validate_extension_definition_object(
    item: dict[str, Any],
    errors: list[AfbExportCompatibilityError],
) -> None:
    for field_name in ("id", "name", "description", "created", "modified", "created_by_ref", "schema", "version", "extension_types"):
        if field_name not in item:
            errors.append(_compatibility_error("extension_definition_field_missing", f"extension-definition object missing required field: {field_name}", object_ref=_coerce_non_empty_string(item.get("id"))))

    if _coerce_non_empty_string(item.get("created_by_ref")) != AFB_PINNED_TARGET_IDENTITY_ID:
        errors.append(_compatibility_error("extension_definition_created_by_ref_invalid", "extension-definition created_by_ref must target the pinned identity", object_ref=_coerce_non_empty_string(item.get("id"))))


def _validate_identity_object(
    item: dict[str, Any],
    errors: list[AfbExportCompatibilityError],
) -> None:
    for field_name in ("id", "name", "identity_class", "created", "modified", "created_by_ref"):
        if field_name not in item:
            errors.append(_compatibility_error("identity_field_missing", f"identity object missing required field: {field_name}", object_ref=_coerce_non_empty_string(item.get("id"))))


def _validate_attack_flow_object(item: dict[str, Any], errors: list[AfbExportCompatibilityError]) -> None:
    for field_name in ("id", "name", "scope", "start_refs"):
        if field_name not in item:
            errors.append(_compatibility_error("attack_flow_field_missing", f"attack-flow object missing required field: {field_name}", object_ref=_coerce_non_empty_string(item.get("id"))))

    extensions = item.get("extensions")
    if not isinstance(extensions, dict) or AFB_PINNED_TARGET_EXTENSION_DEFINITION_ID not in extensions:
        errors.append(_compatibility_error("attack_flow_extension_missing", "attack-flow object must include the Attack Flow extension reference", object_ref=_coerce_non_empty_string(item.get("id"))))

    start_refs = item.get("start_refs")
    if not isinstance(start_refs, list):
        errors.append(_compatibility_error("attack_flow_start_refs_invalid", "attack-flow start_refs must be a list", object_ref=_coerce_non_empty_string(item.get("id"))))


def _validate_attack_condition_object(item: dict[str, Any], errors: list[AfbExportCompatibilityError]) -> None:
    description = item.get("description")
    if description is not None and (not isinstance(description, str) or not description.strip()):
        errors.append(_compatibility_error("attack_condition_description_invalid", "attack-condition description must be a non-empty string when present", object_ref=_coerce_non_empty_string(item.get("id"))))
    for field_name in ("on_true_refs", "on_false_refs"):
        refs = item.get(field_name)
        if refs is not None and not isinstance(refs, list):
            errors.append(_compatibility_error("attack_condition_refs_invalid", f"{field_name} must be a list when present", object_ref=_coerce_non_empty_string(item.get("id"))))


def _validate_attack_action_object(item: dict[str, Any], errors: list[AfbExportCompatibilityError]) -> None:
    if not isinstance(item.get("name"), str) or not item.get("name", "").strip():
        errors.append(_compatibility_error("attack_action_name_invalid", "attack-action name must be a non-empty string", object_ref=_coerce_non_empty_string(item.get("id"))))

    description = item.get("description")
    if description is not None and (not isinstance(description, str) or not description.strip()):
        errors.append(_compatibility_error("attack_action_description_invalid", "attack-action description must be a non-empty string when present", object_ref=_coerce_non_empty_string(item.get("id"))))

    for field_name in ("technique_id", "technique_ref", "tactic_id", "tactic_ref", "execution_start", "execution_end"):
        value = item.get(field_name)
        if value is not None and not isinstance(value, str):
            errors.append(_compatibility_error("attack_action_field_invalid", f"{field_name} must be a string when present", object_ref=_coerce_non_empty_string(item.get("id")), details={"field": field_name}))

    for field_name in ("asset_refs", "effect_refs"):
        refs = item.get(field_name)
        if refs is not None and not isinstance(refs, list):
            errors.append(_compatibility_error("attack_action_refs_invalid", f"{field_name} must be a list when present", object_ref=_coerce_non_empty_string(item.get("id")), details={"field": field_name}))


def _validate_attack_operator_object(item: dict[str, Any], errors: list[AfbExportCompatibilityError]) -> None:
    if item.get("operator") not in {"AND", "OR"}:
        errors.append(_compatibility_error("attack_operator_invalid", "attack-operator must use AND or OR", object_ref=_coerce_non_empty_string(item.get("id"))))
    refs = item.get("effect_refs")
    if refs is not None and not isinstance(refs, list):
        errors.append(_compatibility_error("attack_operator_refs_invalid", "attack-operator effect_refs must be a list when present", object_ref=_coerce_non_empty_string(item.get("id"))))


def _validate_attack_asset_object(
    item: dict[str, Any],
    supporting_object_refs: list[str],
    errors: list[AfbExportCompatibilityError],
) -> None:
    if not isinstance(item.get("name"), str) or not item.get("name", "").strip():
        errors.append(_compatibility_error("attack_asset_name_invalid", "attack-asset name must be a non-empty string", object_ref=_coerce_non_empty_string(item.get("id"))))
    if item.get("object_ref") is not None and not isinstance(item.get("object_ref"), str):
        errors.append(_compatibility_error("attack_asset_object_ref_invalid", "attack-asset object_ref must be a string when present", object_ref=_coerce_non_empty_string(item.get("id"))))
    object_ref = _coerce_non_empty_string(item.get("object_ref"))
    if object_ref is not None and supporting_object_refs and object_ref not in supporting_object_refs:
        errors.append(_compatibility_error("attack_asset_object_ref_unregistered", f"attack-asset object_ref is not registered in bundle metadata: {object_ref}", object_ref=_coerce_non_empty_string(item.get("id")), details={"target_ref": object_ref}))


def _compatibility_error(
    code: str,
    message: str,
    *,
    object_ref: str | None = None,
    details: dict[str, Any] | None = None,
) -> AfbExportCompatibilityError:
    return AfbExportCompatibilityError(code=code, message=message, object_ref=object_ref, details=details or {})


def _coerce_non_empty_description(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _coerce_verbatim_description(value: str | None) -> str | None:
    if value is None:
        return None
    return value if value.strip() else None


def _coerce_non_empty_string(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _coerce_string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    output: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        stripped = value.strip()
        if stripped:
            output.append(stripped)
    return output


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _build_external_reference_objects(external_references: list[str]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for reference in _dedupe_preserve_order(_coerce_string_list(external_references)):
        parsed = urlparse(reference)
        if parsed.scheme and (parsed.netloc or parsed.path):
            source_name = parsed.netloc or parsed.path or reference
            refs.append({"source_name": source_name, "url": reference})
            continue
        refs.append({"source_name": reference, "description": reference})
    return refs


def _build_string_list_property(values: Any) -> list[str] | None:
    items = _coerce_string_list(values)
    if not items:
        return None
    return items


def _build_ordered_list_property(values: Any) -> list[list[Any]] | None:
    if not isinstance(values, list) or not values:
        return None
    entries: list[list[Any]] = []
    for index, value in enumerate(values, start=1):
        if value is None:
            continue
        entries.append([f"item-{index}", value])
    return entries or None


def _build_string_list_entries(values: Any) -> list[list[Any]] | None:
    items = _dedupe_preserve_order(_coerce_string_list(values))
    if not items:
        return None
    return [[f"item-{index}", item] for index, item in enumerate(items, start=1)]


def _build_tags_property(values: Any) -> dict[str, bool] | None:
    tags = _dedupe_preserve_order(_coerce_string_list(values))
    if not tags:
        return None
    return {tag: True for tag in tags}


def _build_supporting_object_refs(canonical_flow: CanonicalFlowOutput) -> list[str]:
    refs: list[str] = []
    for node in canonical_flow.nodes:
        if isinstance(node, CanonicalFlowAssetNode):
            object_ref = _coerce_non_empty_string(getattr(node, "object_ref", None))
            if object_ref is not None:
                refs.append(object_ref)
    return _dedupe_preserve_order(refs)


def _build_diagram_export_json_ready(bundle: AfbExportBundle) -> dict[str, Any]:
    canvas = next((item for item in bundle.objects.objects if item.get("type") == "attack-flow"), None)
    if canvas is None:
        canvas = {
            "type": "attack-flow",
            "id": "flow",
            "name": "Untitled Document",
            "scope": "incident",
            "start_refs": [],
        }

    canvas_payload = dict(canvas)
    canvas_payload["external_references"] = _build_external_reference_objects(_collect_canvas_external_references(bundle.metadata.external_references))

    diagram_objects: list[dict[str, Any]] = []
    canvas_export: dict[str, Any] = {
        "id": "flow",
        "instance": bundle.metadata.bundle_id,
        "objects": [],
    }

    canvas_properties = _build_canvas_properties(canvas_payload, bundle.metadata.authors)
    if canvas_properties:
        canvas_export["properties"] = canvas_properties

    for item in bundle.objects.objects:
        object_type = item.get("type")
        if object_type == "attack-flow":
            continue
        diagram_object = _build_diagram_object_export(item)
        if diagram_object is None:
            continue
        canvas_export["objects"].append(diagram_object["instance"])
        diagram_objects.append(diagram_object)

    diagram_objects.insert(0, canvas_export)
    return {
        "schema": "attack_flow_v2",
        "objects": diagram_objects,
    }


def _build_canvas_properties(canvas: dict[str, Any], authors: list[str]) -> list[list[Any]]:
    properties: list[list[Any]] = [["name", canvas.get("name")]]

    description = _coerce_non_empty_description(canvas.get("description"))
    if description is not None:
        properties.append(["description", description])

    scope = _coerce_non_empty_string(canvas.get("scope"))
    if scope is not None:
        properties.append(["scope", scope])

    author_name = authors[0] if authors else "Unknown"
    properties.append(["author", {"name": author_name}])

    external_references = canvas.get("external_references")
    if isinstance(external_references, list) and external_references:
        if all(isinstance(item, dict) for item in external_references):
            properties.append(["external_references", [dict(item) for item in external_references]])
        else:
            properties.append(["external_references", _build_external_reference_objects(_coerce_string_list(external_references))])

    return properties


def _build_diagram_object_export(item: dict[str, Any]) -> dict[str, Any] | None:
    object_type = item.get("type")
    object_id = _coerce_non_empty_string(item.get("id"))
    if object_type is None or object_id is None:
        return None

    if object_type == "attack-action":
        properties: list[list[Any]] = [["name", item.get("name")]]
        description = _coerce_non_empty_description(item.get("description"))
        if description is not None:
            properties.append(["description", description])
        ttp = _build_ttp_property(item)
        if ttp is not None:
            properties.append(["ttp", ttp])
        for field_name in ("execution_start", "execution_end"):
            value = _coerce_non_empty_string(item.get(field_name))
            if value is not None:
                properties.append([field_name, value])
        return _build_block_export("action", object_id, properties)

    if object_type == "attack-condition":
        properties = []
        description = _coerce_non_empty_description(item.get("description"))
        if description is not None:
            properties.append(["description", description])
        return _build_block_export("condition", object_id, properties)

    if object_type == "attack-asset":
        properties = [["name", item.get("name")]]
        description = _coerce_non_empty_description(item.get("description"))
        if description is not None:
            properties.append(["description", description])
        return _build_block_export("asset", object_id, properties)

    if object_type == "attack-operator":
        operator = _coerce_non_empty_string(item.get("operator"))
        if operator is None:
            return None
        template_id = "AND_operator" if operator == "AND" else "OR_operator"
        return _build_block_export(template_id, object_id, [["operator", operator]])

    return None


def _build_block_export(template_id: str, instance: str, properties: list[list[Any]]) -> dict[str, Any]:
    export: dict[str, Any] = {
        "id": template_id,
        "instance": instance,
        "anchors": {},
    }
    if properties:
        export["properties"] = properties
    return export


def _build_ttp_property(item: dict[str, Any]) -> dict[str, Any] | None:
    ttp: dict[str, Any] = {}
    tactic_ref = _coerce_non_empty_string(item.get("tactic_ref")) or _coerce_non_empty_string(item.get("tactic_id"))
    technique_ref = _coerce_non_empty_string(item.get("technique_ref")) or _coerce_non_empty_string(item.get("technique_id"))
    if tactic_ref is not None:
        ttp["tactic"] = tactic_ref
    if technique_ref is not None:
        ttp["technique"] = technique_ref
    return ttp or None


_DIAGRAM_STANDARD_ANCHOR_KEYS = ["0", "30", "60", "90", "120", "150", "180", "210", "240", "270", "300", "330"]
_DIAGRAM_HORIZONTAL_ANCHOR_KEYS = {"0", "30", "150", "180", "210", "330"}
_DIAGRAM_BRANCH_ANCHOR_KEYS = ["branch:True", "branch:False"]
_DIAGRAM_ROOT_VERTICAL_GAP = 520.0
_DIAGRAM_VERTICAL_CHILD_GAP = 420.0
_DIAGRAM_HORIZONTAL_CHILD_GAP = 620.0
_DIAGRAM_SUPPORT_COLUMN_X = 1440.0
_DIAGRAM_SUPPORT_ROW_GAP = 380.0


def _build_diagram_export_json_ready(bundle: AfbExportBundle) -> dict[str, Any]:
    canvas = next((item for item in bundle.objects.objects if item.get("type") == "attack-flow"), None)
    if canvas is None:
        canvas = {
            "type": "attack-flow",
            "id": "flow",
            "name": "Untitled Document",
            "scope": "incident",
            "start_refs": [],
        }

    block_specs, relations = _collect_diagram_graph(bundle)
    block_exports: list[dict[str, Any]] = []
    anchor_exports: list[dict[str, Any]] = []
    latch_exports: list[dict[str, Any]] = []
    handle_exports: list[dict[str, Any]] = []
    line_exports: list[dict[str, Any]] = []
    anchor_index: dict[str, dict[str, Any]] = {}

    for spec in block_specs:
        block_export, anchors = _build_diagram_block_export(spec)
        block_exports.append(block_export)
        anchor_exports.extend(anchors)
        for anchor in anchors:
            anchor_index[anchor["instance"]] = anchor

    for rel in relations:
        line_export, source_latch, target_latch, handle_export = _build_diagram_line_export(rel)
        line_exports.append(line_export)
        latch_exports.extend([source_latch, target_latch])
        handle_exports.append(handle_export)
        source_anchor = anchor_index.get(rel["source_anchor_instance"])
        target_anchor = anchor_index.get(rel["target_anchor_instance"])
        if source_anchor is not None:
            source_anchor.setdefault("latches", []).append(source_latch["instance"])
        if target_anchor is not None:
            target_anchor.setdefault("latches", []).append(target_latch["instance"])

    layout = _build_diagram_layout(block_specs, relations)
    for rel, line_export, handle_export in zip(relations, line_exports, handle_exports):
        source_position = layout.get(rel["source_instance"])
        target_position = layout.get(rel["target_instance"])
        if source_position is not None and target_position is not None:
            handle_position = [
                round((source_position[0] + target_position[0]) / 2.0, 1),
                round((source_position[1] + target_position[1]) / 2.0, 1),
            ]
            handle_export["position"] = handle_position
            layout[handle_export["instance"]] = handle_position

    canvas_export = _build_canvas_export(canvas, bundle.metadata.authors, bundle.metadata.external_references)
    canvas_export["objects"] = [spec["instance"] for spec in block_specs] + [line["instance"] for line in line_exports]

    objects: list[dict[str, Any]] = [canvas_export, *block_exports, *anchor_exports, *latch_exports, *handle_exports, *line_exports]
    payload: dict[str, Any] = {
        "schema": "attack_flow_v2",
        "objects": objects,
        "layout": layout,
        "camera": {"x": 0, "y": 0, "k": 1},
    }
    return payload


def _build_canvas_export(canvas: dict[str, Any], authors: list[str], external_references: list[str]) -> dict[str, Any]:
    canvas_export: dict[str, Any] = {
        "id": "flow",
        "instance": _make_diagram_instance_id("canvas", _coerce_non_empty_string(canvas.get("id")) or "flow"),
        "objects": [],
    }
    canvas_payload = dict(canvas)
    canvas_payload["external_references"] = _build_external_reference_objects(_collect_canvas_external_references(external_references))
    properties = _build_canvas_properties(canvas_payload, authors)
    if properties:
        canvas_export["properties"] = properties
    return canvas_export


def _collect_canvas_external_references(external_references: list[str]) -> list[str]:
    return _dedupe_preserve_order([ref for ref in _coerce_string_list(external_references) if ref])


def _collect_diagram_graph(bundle: AfbExportBundle) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    blocks: list[dict[str, Any]] = []
    relations: list[dict[str, Any]] = []
    block_index: dict[str, dict[str, Any]] = {}

    canvas = next((item for item in bundle.objects.objects if item.get("type") == "attack-flow"), None)
    if canvas is None:
        canvas = {"type": "attack-flow", "id": "flow", "name": "Untitled Document", "scope": "incident", "start_refs": []}

    for item in bundle.objects.objects:
        object_type = item.get("type")
        if object_type == "attack-flow":
            continue
        if object_type in {"attack-action", "attack-condition", "attack-operator", "attack-asset"}:
            spec = _build_main_block_spec(item)
            blocks.append(spec)
            block_index[spec["instance"]] = spec

    for item in bundle.objects.objects:
        if item.get("type") != "attack-action":
            continue
        source = _coerce_non_empty_string(item.get("id"))
        if source is None:
            continue
        relations.extend(_build_action_relations(item, block_index, blocks))

    for item in bundle.objects.objects:
        if item.get("type") != "attack-asset":
            continue
        source = _coerce_non_empty_string(item.get("id"))
        if source is None:
            continue
        relations.extend(_build_asset_relations(item, block_index, blocks))

    if bundle.canonical_flow is not None:
        relations.extend(_build_relations_from_canonical_flow(bundle.canonical_flow, block_index))

    # Add any support nodes referenced by the support relations.
    support_block_index = {spec["instance"]: spec for spec in blocks}
    for rel in relations:
        for side in ("source", "target"):
            support_item = rel.get(f"{side}_support_item")
            if support_item is None:
                continue
            spec = _build_support_block_spec(support_item)
            if spec is None or spec["instance"] in support_block_index:
                continue
            blocks.append(spec)
            support_block_index[spec["instance"]] = spec

    # Rebuild support relations now that support blocks exist.
    relations = _dedupe_relations(relations)

    return blocks, relations


def _build_relations_from_canonical_flow(
    canonical_flow: CanonicalFlowOutput,
    block_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    relations: list[dict[str, Any]] = []
    relation_keys: set[tuple[str, str, str]] = set()
    node_index = {node.id: node for node in canonical_flow.nodes}

    def add_relation(rel: dict[str, Any]) -> None:
        key = (rel["source_instance"], rel["target_instance"], rel["kind"])
        if key in relation_keys:
            return
        relation_keys.add(key)
        relations.append(rel)

    for edge in canonical_flow.edges:
        source_node = next((node for node in canonical_flow.nodes if node.id == edge.source_ref), None)
        target_node = next((node for node in canonical_flow.nodes if node.id == edge.target_ref), None)
        if source_node is None or target_node is None:
            continue

        layout_mode = _edge_layout_mode(source_node.node_kind, edge.edge_type)
        if layout_mode is None:
            continue

        target_kind = getattr(target_node, "node_kind", None)
        if target_kind is None:
            continue

        source_anchor, target_anchor = _edge_anchor_pair(source_node.node_kind, target_kind, edge.edge_type)
        if source_anchor is None or target_anchor is None:
            continue

        source_support_item = _support_item_for_node(source_node)
        target_support_item = _support_item_for_node(target_node)
        add_relation(
            _make_relation(
                source_node.id,
                target_node.id,
                layout_mode,
                source_anchor=source_anchor,
                target_anchor=target_anchor,
                source_support_item=source_support_item,
                target_support_item=target_support_item,
            )
        )

    for action in canonical_flow.nodes:
        if getattr(action, "node_kind", None) != "attack-action":
            continue
        for ref in list(getattr(action, "asset_refs", []) or []) + list(getattr(action, "object_refs", []) or []):
            if not ref:
                continue
            target_node = node_index.get(ref)
            if target_node is None:
                continue
            target_support_item = _support_item_for_node(target_node)
            add_relation(
                _make_relation(
                    action.id,
                    target_node.id,
                    "horizontal",
                    source_anchor="0",
                    target_anchor="180",
                    source_support_item=_support_item_for_node(action),
                    target_support_item=target_support_item,
                )
            )

    action_nodes = [node for node in canonical_flow.nodes if getattr(node, "node_kind", None) == "attack-action"]
    for previous, current in zip(action_nodes, action_nodes[1:]):
        # Keep the sequential chain explicit even if a direct edge already exists.
        # Dedupe later collapses exact duplicates, so this guarantees adjacency.
        add_relation(
            _make_relation(
                previous.id,
                current.id,
                "vertical",
                source_anchor="270",
                target_anchor="90",
                source_support_item=_support_item_for_node(previous),
                target_support_item=_support_item_for_node(current),
            )
        )
    return relations


def _edge_layout_mode(source_kind: Any, edge_type: Any) -> str | None:
    if edge_type == "asset":
        return "horizontal"
    if edge_type in {"true", "false"}:
        return "branch"
    if edge_type == "relationship":
        return "horizontal"
    if source_kind == "attack-operator":
        return "horizontal"
    if source_kind in {"attack-action", "attack-condition"}:
        return "vertical"
    return None


def _edge_anchor_pair(source_kind: Any, target_kind: Any, edge_type: Any) -> tuple[str | None, str | None]:
    if edge_type == "asset":
        return "0", "180"
    if edge_type == "true":
        return "branch:True", "90"
    if edge_type == "false":
        return "branch:False", "90"
    if edge_type == "relationship":
        return "0", "180"
    if source_kind == "attack-operator":
        return "0", "180"
    if source_kind == "attack-condition":
        return "branch:True" if target_kind == "attack-action" else "branch:False", "90"
    return "270", "90"


def _support_item_for_node(node: Any) -> dict[str, Any] | None:
    if getattr(node, "node_kind", None) == "attack-action":
        technique = getattr(node, "technique", None)
        if technique is not None:
            support_item = _build_technique_support_item(technique.model_dump(mode="json") if hasattr(technique, "model_dump") else dict(technique) if isinstance(technique, dict) else {})
            if support_item is not None:
                return support_item
    if getattr(node, "node_kind", None) == "attack-asset":
        stix_properties = getattr(node, "stix_properties", None)
        if isinstance(stix_properties, dict) and stix_properties:
            support = dict(stix_properties)
            support.setdefault("type", _coerce_non_empty_string(getattr(node, "object_ref", None)) or _coerce_non_empty_string(getattr(node, "id", None)) or "attack-asset")
            support.setdefault("kind", support["type"])
            support.setdefault("id", _coerce_non_empty_string(getattr(node, "object_ref", None)) or getattr(node, "id", None))
            return support
        object_ref = _coerce_non_empty_string(getattr(node, "object_ref", None))
        if object_ref is not None:
            support = _build_stix_support_item(object_ref)
            if support is not None:
                return support
    return None


def _build_main_block_spec(item: dict[str, Any]) -> dict[str, Any]:
    object_type = item.get("type")
    object_id = _coerce_non_empty_string(item.get("id")) or ""
    template_id = _main_template_id_for_type(object_type)
    if object_type == "attack-operator":
        template_id = "AND_operator" if _coerce_non_empty_string(item.get("operator")) == "AND" else "OR_operator"
    spec: dict[str, Any] = {
        "kind": object_type,
        "template_id": template_id,
        "instance": object_id,
        "properties": _main_properties_for_item(item),
        "anchor_keys": list(_DIAGRAM_STANDARD_ANCHOR_KEYS) + (_DIAGRAM_BRANCH_ANCHOR_KEYS if object_type == "attack-condition" else []),
    }
    return spec


def _build_support_block_spec(item: dict[str, Any]) -> dict[str, Any] | None:
    template_id, properties = _support_template_and_properties(item)
    instance = _support_instance_for_item(item)
    if template_id is None or instance is None:
        return None
    return {
        "kind": item.get("type"),
        "template_id": template_id,
        "instance": instance,
        "properties": properties,
        "anchor_keys": list(_DIAGRAM_STANDARD_ANCHOR_KEYS),
        "support_item": item,
    }


def _build_action_relations(
    item: dict[str, Any],
    block_index: dict[str, dict[str, Any]],
    blocks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    source = _coerce_non_empty_string(item.get("id"))
    if source is None:
        return []

    relations: list[dict[str, Any]] = []
    source_support_item = _build_technique_support_item(item)

    for ref in _coerce_string_list(item.get("object_refs")):
        target_spec = block_index.get(ref)
        target_support = target_spec.get("support_item") if isinstance(target_spec, dict) else None
        if not isinstance(target_support, dict):
            target_support = _build_stix_support_item(ref)
        if target_support is None:
            continue
        target_support = dict(target_support)
        target_support["diagram_instance"] = _make_diagram_instance_id("support", source, ref, "object")
        support_instance = _support_instance_for_item(target_support)
        if support_instance is not None:
            relations.append(_make_relation(source, support_instance, "horizontal", source_anchor="0", target_anchor="180", source_support_item=source_support_item, target_support_item=target_support))

    for ref in _coerce_string_list(item.get("asset_refs")):
        target_spec = block_index.get(ref)
        target_support = target_spec.get("support_item") if isinstance(target_spec, dict) else None
        if not isinstance(target_support, dict):
            target_support = {"type": "attack-asset", "id": ref, "name": ref}
        target_support = dict(target_support)
        target_support["diagram_instance"] = _make_diagram_instance_id("support", source, ref, "asset")
        support_instance = _support_instance_for_item(target_support)
        if support_instance is not None:
            relations.append(_make_relation(source, support_instance, "horizontal", source_anchor="0", target_anchor="180", source_support_item=source_support_item, target_support_item=target_support))

    for ref in _coerce_string_list(item.get("effect_refs")):
        target_spec = block_index.get(ref)
        target_support = target_spec.get("support_item") if isinstance(target_spec, dict) else None
        if isinstance(target_support, dict):
            relations.append(_make_relation(source, ref, "vertical", source_anchor="270", target_anchor="90", source_support_item=source_support_item, target_support_item=target_support))
        else:
            relations.append(_make_relation(source, ref, "vertical", source_anchor="270", target_anchor="90", source_support_item=source_support_item))

    return relations


def _build_asset_relations(
    item: dict[str, Any],
    block_index: dict[str, dict[str, Any]],
    blocks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    source = _coerce_non_empty_string(item.get("id"))
    object_ref = _coerce_non_empty_string(item.get("object_ref"))
    if source is None or object_ref is None:
        return []
    target_spec = block_index.get(object_ref)
    support_item = target_spec.get("support_item") if isinstance(target_spec, dict) else None
    if not isinstance(support_item, dict):
        support_item = _build_stix_support_item(object_ref)
    if support_item is None:
        return []
    support_instance = _support_instance_for_item(support_item)
    if support_instance is None:
        return []
    return [_make_relation(source, support_instance, "horizontal", source_anchor="0", target_anchor="180", target_support_item=support_item)]


def _make_relation(
    source_instance: str,
    target_instance: str,
    layout_mode: str,
    *,
    source_anchor: str,
    target_anchor: str,
    source_support_item: dict[str, Any] | None = None,
    target_support_item: dict[str, Any] | None = None,
) -> dict[str, Any]:
    relation_key = f"{source_instance}:{source_anchor}->{target_instance}:{target_anchor}:{layout_mode}"
    line_instance = _make_diagram_instance_id("line", relation_key)
    return {
        "kind": layout_mode,
        "source_instance": source_instance,
        "target_instance": target_instance,
        "source_anchor_key": source_anchor,
        "target_anchor_key": target_anchor,
        "source_anchor_instance": _anchor_instance_for(source_instance, source_anchor),
        "target_anchor_instance": _anchor_instance_for(target_instance, target_anchor),
        "instance": line_instance,
        "source_support_item": source_support_item,
        "target_support_item": target_support_item,
    }


def _build_diagram_line_export(rel: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    source_latch_instance = _make_diagram_instance_id("latch", rel["instance"], "source")
    target_latch_instance = _make_diagram_instance_id("latch", rel["instance"], "target")
    handle_instance = _make_diagram_instance_id("handle", rel["instance"], "mid")
    line_export = {
        "id": "dynamic_line",
        "instance": rel["instance"],
        "source": source_latch_instance,
        "target": target_latch_instance,
        "handles": [handle_instance],
    }
    return (
        line_export,
        {"id": "generic_latch", "instance": source_latch_instance},
        {"id": "generic_latch", "instance": target_latch_instance},
        {"id": "generic_handle", "instance": handle_instance},
    )


def _build_diagram_block_export(spec: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    block_export = {
        "id": spec["template_id"],
        "instance": spec["instance"],
        "anchors": {},
    }
    if spec["properties"]:
        block_export["properties"] = spec["properties"]

    anchors: list[dict[str, Any]] = []
    for key in spec["anchor_keys"]:
        anchor_instance = _anchor_instance_for(spec["instance"], key)
        block_export["anchors"][key] = anchor_instance
        anchors.append({
            "id": _anchor_template_id_for_key(key),
            "instance": anchor_instance,
            "latches": [],
        })
    return block_export, anchors


def _build_diagram_layout(block_specs: list[dict[str, Any]], relations: list[dict[str, Any]]) -> dict[str, list[float]]:
    positions: dict[str, list[float]] = {}
    outgoing: dict[str, list[dict[str, Any]]] = {}
    incoming: dict[str, int] = {}
    for spec in block_specs:
        outgoing[spec["instance"]] = []
        incoming.setdefault(spec["instance"], 0)
    for rel in relations:
        outgoing.setdefault(rel["source_instance"], []).append(rel)
        incoming[rel["target_instance"]] = incoming.get(rel["target_instance"], 0) + 1

    root_instances = [spec["instance"] for spec in block_specs if spec["kind"] in {"attack-action", "attack-condition", "attack-operator"} and incoming.get(spec["instance"], 0) == 0]
    if not root_instances:
        root_instances = [spec["instance"] for spec in block_specs if spec["kind"] in {"attack-action", "attack-condition", "attack-operator"}]

    y_cursor = 0.0
    for root in root_instances:
        if root in positions:
            continue
        _place_node(root, 0.0, y_cursor, positions, outgoing, block_specs)
        y_cursor += _DIAGRAM_ROOT_VERTICAL_GAP

    # Place any remaining unpositioned nodes in a support column.
    remaining = [spec["instance"] for spec in block_specs if spec["instance"] not in positions]
    for index, instance in enumerate(remaining):
        positions[instance] = [_DIAGRAM_SUPPORT_COLUMN_X, float(index) * _DIAGRAM_SUPPORT_ROW_GAP]

    return positions


def _place_node(
    instance: str,
    x: float,
    y: float,
    positions: dict[str, list[float]],
    outgoing: dict[str, list[dict[str, Any]]],
    block_specs: list[dict[str, Any]],
) -> None:
    if instance in positions:
        return
    positions[instance] = [x, y]
    spec = next((item for item in block_specs if item["instance"] == instance), None)
    if spec is None:
        return
    relations = outgoing.get(instance, [])
    vertical_children = [rel for rel in relations if rel["kind"] == "vertical"]
    horizontal_children = [rel for rel in relations if rel["kind"] == "horizontal"]
    branch_children = [rel for rel in relations if rel["kind"] == "branch"]

    next_y = y + _DIAGRAM_VERTICAL_CHILD_GAP
    for rel in vertical_children + branch_children:
        child = rel["target_instance"]
        child_spec = next((item for item in block_specs if item["instance"] == child), None)
        if child_spec is not None and child_spec["kind"] not in {"attack-action", "attack-condition", "attack-operator"}:
            continue
        if child not in positions:
            _place_node(child, x, next_y, positions, outgoing, block_specs)
            next_y += _DIAGRAM_VERTICAL_CHILD_GAP

    next_x = x + _DIAGRAM_HORIZONTAL_CHILD_GAP
    for rel in horizontal_children:
        child = rel["target_instance"]
        if child not in positions:
            _place_node(child, next_x, y, positions, outgoing, block_specs)
            next_x += _DIAGRAM_HORIZONTAL_CHILD_GAP


def _main_template_id_for_type(object_type: str | None) -> str:
    if object_type == "attack-action":
        return "action"
    if object_type == "attack-condition":
        return "condition"
    if object_type == "attack-operator":
        return "attack-operator"
    if object_type == "attack-asset":
        return "asset"
    return "action"


def _main_properties_for_item(item: dict[str, Any]) -> list[list[Any]]:
    object_type = item.get("type")
    if object_type == "attack-action":
        properties: list[list[Any]] = [["name", _coerce_non_empty_string(item.get("name")) or _coerce_non_empty_string(item.get("id")) or "Untitled action"]]
        description = _coerce_non_empty_description(item.get("description"))
        if description is not None:
            properties.append(["description", description])
        confidence = item.get("confidence")
        if confidence is not None:
            properties.append(["confidence", confidence])
        ttp = _build_ttp_property(item)
        if ttp is not None:
            properties.append(["ttp", ttp])
        tags = _build_tags_property(item.get("tags"))
        if tags is not None:
            properties.append(["tags", tags])
        for field_name in ("execution_start", "execution_end"):
            value = _coerce_non_empty_string(item.get(field_name))
            if value is not None:
                properties.append([field_name, value])
        return properties
    if object_type == "attack-condition":
        properties = []
        description = _coerce_non_empty_description(item.get("description"))
        if description is not None:
            properties.append(["description", description])
        tags = _build_tags_property(item.get("tags"))
        if tags is not None:
            properties.append(["tags", tags])
        return properties
    if object_type == "attack-operator":
        return [["operator", _coerce_non_empty_string(item.get("operator")) or "OR"]]
    if object_type == "attack-asset":
        properties = [["name", _coerce_non_empty_string(item.get("name")) or _coerce_non_empty_string(item.get("id")) or "Untitled asset"]]
        description = _coerce_non_empty_description(item.get("description"))
        if description is not None:
            properties.append(["description", description])
        tags = _build_tags_property(item.get("tags"))
        if tags is not None:
            properties.append(["tags", tags])
        return properties
    return []


def _support_template_and_properties(item: dict[str, Any]) -> tuple[str | None, list[list[Any]]]:
    kind = item.get("kind") or item.get("type")
    if kind == "attack-pattern":
        return "attack_pattern", _support_properties_from_item(item)
    if kind == "attack-asset":
        return "asset", _support_properties_from_item(item)
    if kind in {"campaign", "grouping", "infrastructure", "intrusion-set", "location", "malware", "tool", "threat-actor", "vulnerability", "report", "note", "identity", "software"}:
        if kind == "identity":
            properties = _support_properties_from_item(item)
            if not any(key == "identity_class" for key, _ in properties):
                properties.append(["identity_class", "organization"])
            return "identity", properties
        return kind.replace("-", "_"), _support_properties_from_item(item)
    if kind in {"artifact", "ipv4-addr", "ipv6-addr", "mac-addr", "domain-name", "email-addr", "url", "file", "directory", "mutex", "process", "user-account"}:
        template = {
            "artifact": "artifact",
            "ipv4-addr": "ipv4_addr",
            "ipv6-addr": "ipv6_addr",
            "mac-addr": "mac_addr",
            "domain-name": "domain_name",
            "email-addr": "email_address",
            "url": "url",
            "file": "file",
            "directory": "directory",
            "mutex": "mutex",
            "process": "process",
            "user-account": "user_account",
        }[kind]
        return template, _support_properties_from_item(item)
    return None, []


def _support_properties_from_item(item: dict[str, Any]) -> list[list[Any]]:
    source = item.get("stix_properties") if isinstance(item.get("stix_properties"), dict) else {}
    merged: dict[str, Any] = {
        **source,
        **{
            key: value
            for key, value in item.items()
            if key not in {"type", "kind", "id", "instance", "properties", "support_item", "stix_properties"} and value is not None
        },
    }
    tags = merged.get("tags")
    if isinstance(tags, list):
        tag_entries = _build_tags_property(tags)
        if tag_entries is not None:
            merged["tags"] = tag_entries
        else:
            merged.pop("tags", None)
    for key, value in list(merged.items()):
        if isinstance(value, list) and key != "tags":
            list_entries = _build_string_list_entries(value) or _build_ordered_list_property(value)
            if list_entries is not None:
                merged[key] = list_entries
            else:
                merged.pop(key, None)
    return [[key, value] for key, value in merged.items()]


def _support_properties_for_kind(kind: str, value: Any) -> list[list[Any]]:
    text = _coerce_non_empty_string(value) or kind
    if kind in {"domain-name", "email-addr", "ipv4-addr", "ipv6-addr", "mac-addr", "url"}:
        return [["value", text]]
    if kind == "file":
        return [["name", text]]
    if kind == "directory":
        return [["path", text]]
    if kind == "process":
        return [["command_line", text]]
    if kind == "user-account":
        return [["display_name", text]]
    if kind == "mutex":
        return [["name", text]]
    if kind == "artifact":
        return [["mime_type", "application/octet-stream"]]
    return [["name", text]]


def _support_instance_for_item(item: dict[str, Any]) -> str | None:
    candidate = _coerce_non_empty_string(item.get("diagram_instance")) or _coerce_non_empty_string(item.get("id")) or _coerce_non_empty_string(item.get("object_ref")) or _coerce_non_empty_string(item.get("technique_ref")) or _coerce_non_empty_string(item.get("technique_id"))
    return candidate


def _build_technique_support_item(item: dict[str, Any]) -> dict[str, Any] | None:
    technique_ref = _coerce_non_empty_string(item.get("technique_ref")) or _coerce_non_empty_string(item.get("technique_id"))
    if technique_ref is None:
        return None
    support_item = {
        "type": "attack-pattern",
        "kind": "attack-pattern",
        "id": technique_ref,
        "name": _coerce_non_empty_string(item.get("technique_name")) or technique_ref,
    }
    description = _coerce_non_empty_description(item.get("technique_description") or item.get("description"))
    if description is not None:
        support_item["description"] = description
    aliases = _coerce_string_list(item.get("technique_aliases") or item.get("aliases"))
    if aliases:
        support_item["aliases"] = aliases
    kill_chain_phases = _coerce_string_list(item.get("technique_kill_chain_phases") or item.get("kill_chain_phases"))
    if kill_chain_phases:
        support_item["kill_chain_phases"] = kill_chain_phases
    tags = _coerce_string_list(item.get("technique_tags") or item.get("tags"))
    if tags:
        support_item["tags"] = tags
    return support_item


def _build_stix_support_item(ref: str) -> dict[str, Any] | None:
    template_id, properties = _infer_stix_template_and_properties(ref)
    if template_id is None:
        return None
    return {
        "type": template_id.replace("_", "-"),
        "kind": template_id.replace("_", "-"),
        "id": ref,
        "instance": ref,
        "properties": properties,
    }


def _infer_stix_template_and_properties(ref: str) -> tuple[str | None, list[list[Any]]]:
    prefix = ref.split("--", 1)[0]
    if prefix in {"attack-pattern", "campaign", "grouping", "infrastructure", "intrusion-set", "location", "malware", "tool", "threat-actor", "vulnerability", "report", "note"}:
        return prefix.replace("-", "_"), [["name", ref]]
    if prefix == "identity":
        return "identity", [["name", ref], ["identity_class", "organization"]]
    if prefix in {"artifact", "ipv4-addr", "ipv6-addr", "mac-addr", "domain-name", "email-addr", "url", "file", "directory", "mutex", "process", "software", "user-account"}:
        template = {
            "artifact": "artifact",
            "ipv4-addr": "ipv4_addr",
            "ipv6-addr": "ipv6_addr",
            "mac-addr": "mac_addr",
            "domain-name": "domain_name",
            "email-addr": "email_address",
            "url": "url",
            "file": "file",
            "directory": "directory",
            "mutex": "mutex",
            "process": "process",
            "software": "software",
            "user-account": "user_account",
        }[prefix]
        return template, _support_properties_for_kind(prefix, ref)
    return None, []


def _dedupe_relations(relations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str, str]] = set()
    output: list[dict[str, Any]] = []
    for rel in relations:
        key = (
            rel["source_instance"],
            rel["target_instance"],
            rel["source_anchor_key"],
            rel["target_anchor_key"],
            rel["kind"],
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(rel)
    return output


def _anchor_instance_for(block_instance: str, anchor_key: str) -> str:
    return _make_diagram_instance_id("anchor", block_instance, anchor_key)


def _anchor_template_id_for_key(anchor_key: str) -> str:
    if anchor_key in _DIAGRAM_HORIZONTAL_ANCHOR_KEYS:
        return "horizontal_anchor"
    return "vertical_anchor"


def _make_diagram_instance_id(*parts: str) -> str:
    return f"instance--{uuid5(NAMESPACE_URL, ':'.join(parts))}"
