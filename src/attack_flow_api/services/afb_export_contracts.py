from typing import Any, Literal

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
    technique_id: str | None = None
    technique_ref: str | None = None
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
    schema: str = Field(default=AFB_PINNED_TARGET_EXTENSION_SCHEMA_URL, min_length=1)
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
        )
    )


def assemble_afb_export_bundle(canonical_flow: CanonicalFlowOutput) -> AfbExportBundle:
    bundle = build_afb_export_bundle(
        _build_deterministic_bundle_id(canonical_flow.metadata.flow_id),
        canonical_flow=canonical_flow,
    )
    export_objects = _build_export_object_models(canonical_flow)
    prune_errors = _prune_invalid_export_references(export_objects)
    bundle.objects.objects = [obj.model_dump(mode="json") for obj in export_objects]
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
        technique_id=_coerce_non_empty_string(getattr(technique, "technique_id", None)),
        technique_ref=_coerce_non_empty_string(getattr(technique, "technique_ref", None)),
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
        refs.append({"source_name": reference, "url": reference})
    return refs


def _build_supporting_object_refs(canonical_flow: CanonicalFlowOutput) -> list[str]:
    refs: list[str] = []
    for node in canonical_flow.nodes:
        if isinstance(node, CanonicalFlowAssetNode):
            object_ref = _coerce_non_empty_string(getattr(node, "object_ref", None))
            if object_ref is not None:
                refs.append(object_ref)
    return _dedupe_preserve_order(refs)
