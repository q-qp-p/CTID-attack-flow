import json
from dataclasses import dataclass
from typing import Any


class StixJsonValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class StixJsonValidationResult:
    stix_json_kind: str
    stix_json_valid: bool
    object_count: int


def validate_stix_json_bundle_shape(file_bytes: bytes) -> StixJsonValidationResult:
    payload = _parse_json_object(file_bytes)

    payload_type = payload.get("type")
    if payload_type != "bundle":
        raise StixJsonValidationError(
            "stix_json_not_bundle",
            "stix json payload must have top-level type 'bundle'",
        )

    objects = payload.get("objects")
    if not isinstance(objects, list):
        raise StixJsonValidationError(
            "stix_json_invalid_bundle_structure",
            "stix json bundle must include an objects array",
        )

    bundle_id = payload.get("id")
    if bundle_id is not None and (not isinstance(bundle_id, str) or not bundle_id.startswith("bundle--")):
        raise StixJsonValidationError(
            "stix_json_invalid_bundle_id",
            "stix json bundle id must start with 'bundle--' when present",
        )

    return StixJsonValidationResult(
        stix_json_kind="bundle",
        stix_json_valid=True,
        object_count=len(objects),
    )


def _parse_json_object(file_bytes: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(file_bytes.decode("utf-8-sig"))
    except UnicodeDecodeError as exc:
        raise StixJsonValidationError(
            "stix_json_invalid_encoding",
            "stix json must be valid UTF-8",
        ) from exc
    except json.JSONDecodeError as exc:
        raise StixJsonValidationError(
            "stix_json_malformed",
            "stix json payload is malformed",
        ) from exc

    if not isinstance(parsed, dict):
        raise StixJsonValidationError(
            "stix_json_invalid_root",
            "stix json payload must be a top-level JSON object",
        )
    return parsed
