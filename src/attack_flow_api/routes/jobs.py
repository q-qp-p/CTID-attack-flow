import json
from dataclasses import dataclass
from datetime import UTC
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.datastructures import UploadFile

from attack_flow_api.errors import BadRequestError, ConflictError, NotFoundError, PayloadTooLargeError
from attack_flow_api.audit_contracts import JobAuditResponse
from attack_flow_api.services.file_upload import FileUploadValidationError, validate_and_describe_upload
from attack_flow_api.services.stix_json_validation import (
    StixJsonValidationError,
    validate_stix_json_bundle_shape,
)
from attack_flow_api.services.text_normalization import normalize_raw_text
from attack_flow_api.storage.repositories import InputSourceCreate, JobCreate


router = APIRouter(tags=["jobs"])


class JobSubmissionRequest(BaseModel):
    input_type: str
    text: str | None = None
    url: str | None = None
    metadata: dict[str, Any] | None = None
    options: dict[str, Any] | None = None

    model_config = ConfigDict(extra="forbid")


class JobSubmissionResponse(BaseModel):
    job_id: str
    status: str
    submitted_at: str
    poll_url: str
    request_id: str


class JobInputSummary(BaseModel):
    input_type: str | None = None
    original_filename: str | None = None
    title: str | None = None


class JobArtifactsSummary(BaseModel):
    has_stix: bool
    has_afb: bool
    stix_url: str | None = None
    afb_url: str | None = None


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    stage: str
    created_at: str
    updated_at: str
    completed_at: str | None = None
    input: JobInputSummary
    artifacts: JobArtifactsSummary
    request_id: str


class JobDeleteResponse(BaseModel):
    job_id: str
    deleted: bool
    request_id: str


class JobResultResponse(BaseModel):
    job_id: str
    status: str
    result: dict[str, Any]
    request_id: str


@dataclass(slots=True)
class SubmissionPayload:
    source_type: str
    source_url: str | None = None
    content_text: str | None = None
    raw_text: str | None = None
    normalized_text: str | None = None
    normalized_char_count: int | None = None
    normalization_version: str | None = None
    original_name: str | None = None
    storage_path: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    metadata: dict[str, Any] | None = None
    options: dict[str, Any] | None = None
    title: str | None = None
    case_id: str | None = None
    source_name: str | None = None
    stored_filename: str | None = None
    detected_mime_type: str | None = None
    file_class: str | None = None
    stix_json_kind: str | None = None
    stix_json_valid: bool | None = None
    ingestion_error_code: str | None = None
    ingestion_error_message: str | None = None
    sha256: str | None = None


@router.post("/jobs", response_model=JobSubmissionResponse, status_code=202)
async def submit_job(request: Request) -> JobSubmissionResponse:
    """Submit a job from JSON text/url input or multipart file upload.

    Supported modes:
    - `application/json` with `input_type=text` and non-empty `text`
    - `application/json` with `input_type=url` and non-empty `url`
    - `multipart/form-data` with required `file` and optional `metadata`/`options`

    Multipart file behavior:
    - Supported file classes: PDF, plaintext/markdown text, and STIX JSON bundle uploads.
    - Upload size is enforced using configured byte limits.
    - Files are stored with server-generated names; client filenames are metadata only.
    - Plaintext and PDF inputs are extracted and normalized asynchronously for narrative processing.
    - STIX 2.1 bundle JSON is parsed deterministically after routing as `stix_json`.
    - OpenCTI-style custom properties are tolerated when core bundle/object structure is valid.
    - Explicit ATT&CK references are extracted deterministically when present in source data.
    - Relevant entities and explicit relationships are extracted into a structured payload.
    - Narrative text from report/note/description fields is captured for downstream processing.
    - Unsupported file types or malformed payloads fail with structured error responses.

    Canonical normalization behavior:
    - Supported input classes (text, URL-derived narrative, document-derived narrative, STIX/OpenCTI)
      produce a canonical normalized representation for downstream stages.
    - Narrative inputs contribute normalized narrative text.
    - STIX/OpenCTI inputs consume deterministic AFA-24 structured extraction outputs.
    - Explicit ATT&CK refs, entities, relationships, and provenance are preserved in the
      canonical normalized package.
    - Content budgeting/truncation is applied explicitly to canonical normalized text where needed.

    Text submission behavior:
    - Raw text is normalized deterministically (line endings/whitespace) before processing.
    - Maximum text size is enforced via configured character limit.
    - Normalized text is persisted for downstream pipeline stages.

    URL submission behavior:
    - URL jobs are fetched asynchronously by the worker after queuing.
    - Only `http` and `https` URLs are supported.
    - Unsafe/internal destinations are blocked during URL safety checks.
    - Redirect count, connect/read timeouts, and response size are bounded.
    - HTML content is extracted into normalized text for downstream stages.
    - Unsupported content types are marked failed during async processing.

    Optional `metadata` and `options` are persisted when provided.

    Submission is non-blocking: this endpoint queues work and returns `202 Accepted`.
    An in-process worker advances queued jobs asynchronously through lifecycle stages.
    """
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        payload = await _parse_json_payload(request)
        submission = _submission_from_json(
            payload,
            raw_text_max_chars=request.app.state.settings.raw_text_max_chars,
        )
    elif content_type.startswith("multipart/form-data"):
        submission = await _submission_from_multipart(request)
    else:
        raise BadRequestError(
            code="unsupported_content_type",
            message="Content-Type must be application/json or multipart/form-data",
            details=[],
        )

    persistence_service = request.app.state.persistence_service
    input_source_id = str(uuid4())
    input_source = persistence_service.create_input_source(
        InputSourceCreate(
            id=input_source_id,
            type=submission.source_type,
            source_url=submission.source_url,
            content_text=submission.content_text,
            raw_text=submission.raw_text,
            normalized_text=submission.normalized_text,
            normalized_char_count=submission.normalized_char_count,
            normalization_version=submission.normalization_version,
            original_name=submission.original_name,
            storage_path=submission.storage_path,
            mime_type=submission.mime_type,
            size_bytes=submission.size_bytes,
            metadata_json=_serialize_optional_json(submission.metadata),
            options_json=_serialize_optional_json(submission.options),
            title=submission.title,
            case_id=submission.case_id,
            source_name=submission.source_name,
            stored_filename=submission.stored_filename,
            detected_mime_type=submission.detected_mime_type,
            file_class=submission.file_class,
            stix_json_kind=submission.stix_json_kind,
            stix_json_valid=submission.stix_json_valid,
            ingestion_error_code=submission.ingestion_error_code,
            ingestion_error_message=submission.ingestion_error_message,
            sha256=submission.sha256,
        )
    )
    return _create_queued_job_response(request, input_source.id)


async def _parse_json_payload(request: Request) -> JobSubmissionRequest:
    try:
        raw_payload = await request.json()
    except Exception as exc:
        raise RequestValidationError([]) from exc

    try:
        return JobSubmissionRequest.model_validate(raw_payload)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


def _submission_from_json(payload: JobSubmissionRequest, raw_text_max_chars: int) -> SubmissionPayload:
    normalized_input_type = payload.input_type.strip().lower()
    raw_text = payload.text if isinstance(payload.text, str) else None
    text = raw_text.strip() if isinstance(raw_text, str) else None
    url = payload.url.strip() if isinstance(payload.url, str) else None

    if normalized_input_type not in {"text", "url"}:
        raise BadRequestError(
            code="invalid_input_type",
            message="input_type must be one of: text, url",
            details=[],
        )

    if normalized_input_type == "text":
        if not text:
            raise BadRequestError(
                code="invalid_text_input",
                message="text input requires a non-empty text value",
                details=[],
            )
        if len(text) > raw_text_max_chars:
            raise PayloadTooLargeError(
                code="text_too_large",
                message=f"text input exceeds maximum size of {raw_text_max_chars} characters",
                details=[],
            )
        if url:
            raise BadRequestError(
                code="conflicting_input_fields",
                message="url must not be provided when input_type is text",
                details=[],
            )

    if normalized_input_type == "url":
        if not url:
            raise BadRequestError(
                code="invalid_url_input",
                message="url input requires a non-empty url value",
                details=[],
            )
        parsed_url = urlsplit(url)
        if parsed_url.scheme.lower() not in {"http", "https"}:
            raise BadRequestError(
                code="invalid_url_scheme",
                message="url scheme must be http or https",
                details=[],
            )
        if text:
            raise BadRequestError(
                code="conflicting_input_fields",
                message="text must not be provided when input_type is url",
                details=[],
            )

    normalized_text = None
    normalized_char_count = None
    normalization_version = None
    title = _coerce_optional_metadata_str(payload.metadata, "title")
    case_id = _coerce_optional_metadata_str(payload.metadata, "case_id")
    source_name = _coerce_optional_metadata_str(payload.metadata, "source_name")
    if normalized_input_type == "text" and raw_text is not None:
        normalized_result = normalize_raw_text(raw_text)
        normalized_text = normalized_result.text
        normalized_char_count = len(normalized_text)
        normalization_version = normalized_result.version

    return SubmissionPayload(
        source_type=normalized_input_type,
        source_url=url if normalized_input_type == "url" else None,
        content_text=normalized_text,
        raw_text=(raw_text if normalized_input_type == "text" else None),
        normalized_text=normalized_text,
        normalized_char_count=normalized_char_count,
        normalization_version=normalization_version,
        metadata=payload.metadata,
        options=payload.options,
        title=title,
        case_id=case_id,
        source_name=source_name,
    )


def _coerce_optional_metadata_str(metadata: dict[str, Any] | None, key: str) -> str | None:
    if metadata is None:
        return None
    value = metadata.get(key)
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    return candidate


async def _submission_from_multipart(request: Request) -> SubmissionPayload:
    form_data = await request.form()
    if (
        form_data.get("input_type") is not None
        or form_data.get("text") is not None
        or form_data.get("url") is not None
    ):
        raise BadRequestError(
            code="conflicting_input_fields",
            message="multipart submission supports file input only",
            details=[],
        )

    upload_file = form_data.get("file")
    if not isinstance(upload_file, UploadFile):
        raise BadRequestError(
            code="missing_file",
            message="multipart submission requires a file field",
            details=[],
        )

    metadata = _parse_optional_json_object(form_data.get("metadata"), "metadata")
    options = _parse_optional_json_object(form_data.get("options"), "options")

    file_bytes = await upload_file.read()
    settings = request.app.state.settings
    try:
        upload_info = validate_and_describe_upload(
            file_bytes=file_bytes,
            original_name=upload_file.filename,
            declared_mime_type=upload_file.content_type,
            upload_max_bytes=settings.upload_max_bytes,
            allowed_file_classes=_split_csv_lower(settings.upload_allowed_file_classes),
            allowed_mime_types=_split_csv_lower(settings.upload_allowed_mime_types),
        )
    except FileUploadValidationError as exc:
        if exc.code == "file_too_large":
            raise PayloadTooLargeError(code=exc.code, message=exc.message, details=[])
        raise BadRequestError(code=exc.code, message=exc.message, details=[])

    file_storage = request.app.state.file_storage
    stored_file = file_storage.write_upload(file_bytes, extension=upload_info.preferred_extension)

    stix_json_kind = None
    stix_json_valid = None
    ingestion_error_code = None
    ingestion_error_message = None
    if upload_info.file_class == "stix_json":
        try:
            stix_validation = validate_stix_json_bundle_shape(file_bytes)
            stix_json_kind = stix_validation.stix_json_kind
            stix_json_valid = stix_validation.stix_json_valid
        except StixJsonValidationError as exc:
            raise BadRequestError(code=exc.code, message=exc.message, details=[])

    return SubmissionPayload(
        source_type="file",
        original_name=upload_info.sanitized_original_name,
        mime_type=upload_file.content_type,
        size_bytes=stored_file.size_bytes,
        storage_path=stored_file.relative_path,
        stored_filename=stored_file.filename,
        detected_mime_type=upload_info.detected_mime_type,
        file_class=upload_info.file_class,
        stix_json_kind=stix_json_kind,
        stix_json_valid=stix_json_valid,
        ingestion_error_code=ingestion_error_code,
        ingestion_error_message=ingestion_error_message,
        sha256=upload_info.sha256_hex,
        raw_text=None,
        normalized_text=None,
        normalized_char_count=None,
        normalization_version=None,
        metadata=metadata,
        options=options,
        source_name=None,
        title=None,
        case_id=None,
    )


def _split_csv_lower(value: str) -> set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def _parse_optional_json_object(raw_value: object, field_name: str) -> dict[str, Any] | None:
    if raw_value is None:
        return None
    if not isinstance(raw_value, str):
        raise BadRequestError(
            code="invalid_multipart_field",
            message=f"{field_name} must be a JSON object string",
            details=[],
        )
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        raise BadRequestError(
            code="invalid_json_field",
            message=f"{field_name} must be valid JSON",
            details=[],
        )
    if not isinstance(parsed, dict):
        raise BadRequestError(
            code="invalid_json_field",
            message=f"{field_name} must be a JSON object",
            details=[],
        )
    return parsed


def _serialize_optional_json(value: dict[str, Any] | None) -> str | None:
    if value is None:
        return None
    return json.dumps(value)


def _create_queued_job_response(request: Request, input_source_id: str) -> JobSubmissionResponse:
    persistence_service = request.app.state.persistence_service
    job = persistence_service.create_job(
        JobCreate(
            id=str(uuid4()),
            status="queued",
            stage="queued",
            input_source_id=input_source_id,
            request_id=request.state.request_id,
        )
    )
    input_source = persistence_service.get_input_source(input_source_id)
    if input_source is not None:
        persistence_service.record_job_submitted(
            job=job,
            input_source_id=input_source_id,
            source_type=input_source.type,
            request_id=request.state.request_id,
        )
    persistence_service.record_job_queued(job=job, request_id=request.state.request_id)
    if input_source is not None and input_source.type == "text" and input_source.normalized_text is not None:
        persistence_service.record_job_event(
            job=job,
            event_type="text_normalized",
            source_component="api",
            message="text normalized",
            details={
                "input_source_id": input_source.id,
                "source_type": input_source.type,
                "normalized_char_count": input_source.normalized_char_count,
                "normalization_version": input_source.normalization_version,
            },
        )
    settings = request.app.state.settings
    submitted_at = job.created_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return JobSubmissionResponse(
        job_id=job.id,
        status=job.status,
        submitted_at=submitted_at,
        poll_url=f"{settings.api_prefix}/jobs/{job.id}",
        request_id=request.state.request_id,
    )


submit_job.openapi_extra = {
    "requestBody": {
        "required": True,
        "content": {
            "application/json": {
                "schema": {
                    "oneOf": [
                        {
                            "type": "object",
                            "required": ["input_type", "text"],
                            "properties": {
                                "input_type": {"type": "string", "enum": ["text"]},
                                "text": {"type": "string", "minLength": 1},
                                "metadata": {"type": "object", "additionalProperties": True},
                                "options": {"type": "object", "additionalProperties": True},
                            },
                            "additionalProperties": False,
                        },
                        {
                            "type": "object",
                            "required": ["input_type", "url"],
                            "properties": {
                                "input_type": {"type": "string", "enum": ["url"]},
                                "url": {"type": "string", "minLength": 1},
                                "metadata": {"type": "object", "additionalProperties": True},
                                "options": {"type": "object", "additionalProperties": True},
                            },
                            "additionalProperties": False,
                        },
                    ]
                },
                "examples": {
                    "text_submission": {
                        "summary": "JSON text submission",
                        "value": {
                            "input_type": "text",
                            "text": "investigation content",
                            "metadata": {"source": "manual"},
                            "options": {"priority": "normal"},
                        },
                    },
                    "url_submission": {
                        "summary": "JSON URL submission",
                        "value": {
                            "input_type": "url",
                            "url": "https://example.com/report",
                            "metadata": {"source": "feed"},
                            "options": {"priority": "normal"},
                        },
                    },
                },
            },
            "multipart/form-data": {
                "schema": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {
                        "file": {
                            "type": "string",
                            "format": "binary",
                            "description": (
                                "Supported classes: PDF, plaintext/markdown text, and STIX JSON bundles. "
                                "Upload size limits are enforced."
                            ),
                        },
                        "metadata": {
                            "type": "string",
                            "description": "Optional JSON object string",
                        },
                        "options": {
                            "type": "string",
                            "description": "Optional JSON object string",
                        },
                    },
                    "additionalProperties": False,
                },
                "encoding": {
                    "metadata": {"contentType": "application/json"},
                    "options": {"contentType": "application/json"},
                },
                "examples": {
                    "file_submission": {
                        "summary": "Multipart file submission",
                        "value": {
                            "file": "<binary>",
                            "metadata": '{"source":"upload"}',
                            "options": '{"priority":"high"}',
                        },
                    }
                },
            },
        },
    },
    "responses": {
        "413": {
            "description": "Submission payload exceeds configured size limits",
            "content": {
                "application/json": {
                    "examples": {
                        "text_too_large": {
                            "value": {
                                "error": {
                                    "code": "text_too_large",
                                    "message": "text input exceeds maximum size of <N> characters",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "file_too_large": {
                            "value": {
                                "error": {
                                    "code": "file_too_large",
                                    "message": "file upload exceeds maximum size of <N> bytes",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                    }
                }
            },
        },
        "400": {
            "description": "Structured validation errors for invalid submission shape, unsupported files, malformed STIX JSON, or invalid STIX bundle structure",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_url_input": {
                            "value": {
                                "error": {
                                    "code": "invalid_url_input",
                                    "message": "url input requires a non-empty url value",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "unsupported_file_type": {
                            "value": {
                                "error": {
                                    "code": "unsupported_file_type",
                                    "message": "uploaded file type is not supported",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "stix_json_malformed": {
                            "value": {
                                "error": {
                                    "code": "stix_json_malformed",
                                    "message": "stix json payload is malformed",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "stix_json_invalid_bundle_structure": {
                            "value": {
                                "error": {
                                    "code": "stix_json_invalid_bundle_structure",
                                    "message": "stix json bundle must include an objects array",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        }
                    }
                }
            },
        }
    },
}


@router.get(
    "/jobs/{job_id}",
    response_model=JobStatusResponse,
    responses={
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "job_not_found",
                            "message": "Job not found",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        }
    },
)
def get_job_status(request: Request, job_id: str) -> JobStatusResponse:
    """Retrieve current job state.

    Jobs progress asynchronously through lifecycle stages:
    queued, fetching, extracting, normalizing, ai_extraction,
    flow_building, exporting, completed, failed.

    Failed jobs include failure state via status/stage and are surfaced by this endpoint.

    For URL jobs, async worker processing may fail due to URL safety checks, bounded fetch
    limits (redirects/timeouts/size), or unsupported content type.

    For file jobs, async worker processing may fail due to extraction/validation issues
    (for example decode failures, unreadable PDFs, or malformed STIX JSON).

    For STIX file jobs, asynchronous processing performs deterministic bundle parsing,
    inventory/entity/relationship extraction, explicit ATT&CK reference extraction,
    and narrative text capture from report/note/description fields.

    During `ai_extraction`, orchestration consumes canonical normalized package input
    and may run in `full_extraction` or `enrichment` mode. Deterministic STIX/OpenCTI
    findings remain authoritative and can reduce or bypass provider invocation when
    sufficient. Intermediate extraction output is constrained to an AFB-compatible
    shape with grounded-only ATT&CK mappings, verbatim action excerpts, AND/OR
    operators, and true/false condition values.

    Downstream processing should read canonical normalized package content when available
    instead of re-reading source-specific raw fields ad hoc.
    """
    persistence_service = request.app.state.persistence_service
    job = _get_job_or_404(persistence_service, job_id)

    input_summary = JobInputSummary()
    if job.input_source_id is not None:
        input_source = persistence_service.get_input_source(job.input_source_id)
        if input_source is not None:
            input_summary = JobInputSummary(
                input_type=input_source.type,
                original_filename=input_source.original_name,
                title=input_source.title,
            )

    artifacts = persistence_service.list_artifacts(job_id=job.id)
    has_stix = any(artifact.type == "stix" for artifact in artifacts)
    has_afb = any(artifact.type == "afb" for artifact in artifacts)
    api_prefix = request.app.state.settings.api_prefix

    return JobStatusResponse(
        job_id=job.id,
        status=job.status,
        stage=job.stage,
        created_at=_to_utc_z(job.created_at),
        updated_at=_to_utc_z(job.updated_at),
        completed_at=_to_utc_z(job.completed_at),
        input=input_summary,
        artifacts=JobArtifactsSummary(
            has_stix=has_stix,
            has_afb=has_afb,
            stix_url=f"{api_prefix}/jobs/{job.id}/artifacts/stix" if has_stix else None,
            afb_url=f"{api_prefix}/jobs/{job.id}/artifacts/afb" if has_afb else None,
        ),
        request_id=request.state.request_id,
    )


@router.delete(
    "/jobs/{job_id}",
    response_model=JobDeleteResponse,
    responses={
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "job_not_found",
                            "message": "Job not found",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        }
    },
)
def delete_job(request: Request, job_id: str) -> JobDeleteResponse:
    persistence_service = request.app.state.persistence_service
    file_storage = request.app.state.file_storage

    job = _get_job_or_404(persistence_service, job_id)

    artifact_paths = [artifact.path for artifact in persistence_service.list_artifacts(job_id=job.id)]
    input_storage_path = None
    if job.input_source_id is not None:
        input_source = persistence_service.get_input_source(job.input_source_id)
        if input_source is not None:
            input_storage_path = input_source.storage_path

    for artifact_path in artifact_paths:
        try:
            file_storage.delete_stored_file(artifact_path)
        except FileNotFoundError:
            pass

    if input_storage_path:
        try:
            file_storage.delete_stored_file(input_storage_path)
        except FileNotFoundError:
            pass

    persistence_service.delete_artifacts_for_job(job.id)
    persistence_service.delete_job(job.id)
    if job.input_source_id is not None and persistence_service.count_jobs_by_input_source(job.input_source_id) == 0:
        persistence_service.delete_input_source(job.input_source_id)

    return JobDeleteResponse(job_id=job.id, deleted=True, request_id=request.state.request_id)


@router.get(
    "/jobs/{job_id}/artifacts/stix",
    responses={
        200: {
            "description": "Download STIX artifact as JSON file",
            "content": {"application/json": {}},
        },
        404: {
            "description": "Job or STIX artifact not found",
            "content": {
                "application/json": {
                    "examples": {
                        "job_not_found": {
                            "value": {
                                "error": {
                                    "code": "job_not_found",
                                    "message": "Job not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "artifact_not_found": {
                            "value": {
                                "error": {
                                    "code": "artifact_not_found",
                                    "message": "stix artifact not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                    }
                }
            },
        },
    },
)
def download_job_stix_artifact(request: Request, job_id: str) -> FileResponse:
    return _download_job_artifact(
        request,
        job_id=job_id,
        artifact_type="stix",
        download_extension="json",
    )


@router.get(
    "/jobs/{job_id}/artifacts/afb",
    responses={
        200: {
            "description": "Download AFB artifact as file (.afb filename)",
            "content": {"application/json": {}},
        },
        404: {
            "description": "Job or AFB artifact not found",
            "content": {
                "application/json": {
                    "examples": {
                        "job_not_found": {
                            "value": {
                                "error": {
                                    "code": "job_not_found",
                                    "message": "Job not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                        "artifact_not_found": {
                            "value": {
                                "error": {
                                    "code": "artifact_not_found",
                                    "message": "afb artifact not found",
                                    "details": [],
                                },
                                "request_id": "<request-id>",
                            }
                        },
                    }
                }
            },
        },
    },
)
def download_job_afb_artifact(request: Request, job_id: str) -> FileResponse:
    return _download_job_artifact(
        request,
        job_id=job_id,
        artifact_type="afb",
        download_extension="afb",
    )


def _download_job_artifact(
    request: Request,
    job_id: str,
    artifact_type: str,
    download_extension: str,
) -> FileResponse:
    persistence_service = request.app.state.persistence_service
    file_storage = request.app.state.file_storage

    job = _get_job_or_404(persistence_service, job_id)

    artifact = _get_artifact_or_404(persistence_service, job.id, artifact_type)
    absolute_path = _resolve_artifact_path_or_404(file_storage, artifact.path, artifact_type)

    return FileResponse(
        path=absolute_path,
        media_type="application/json",
        filename=f"{job.id}-{artifact_type}.{download_extension}",
    )


@router.get(
    "/jobs/{job_id}/result",
    response_model=JobResultResponse,
    responses={
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "job_not_found",
                            "message": "Job not found",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        },
        409: {
            "description": "Result not ready",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "result_not_ready",
                            "message": "Result is not ready",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        },
    },
)
def get_job_result(request: Request, job_id: str) -> JobResultResponse:
    """Retrieve structured result when available.

    Returns `409` while asynchronous processing is still in progress or result data
    is not yet available.

    Note: before final result materialization, normalized canonical source packages are
    persisted per input source and used by downstream orchestration/extraction stages.
    Result payloads in this phase represent intermediate constrained extraction output
    rather than final flow graph/export artifacts.
    """
    persistence_service = request.app.state.persistence_service
    job = _get_job_or_404(persistence_service, job_id)

    if not job.result_json:
        raise ConflictError(code="result_not_ready", message="Result is not ready", details=[])

    try:
        parsed_result = json.loads(job.result_json)
    except json.JSONDecodeError:
        raise ConflictError(code="result_not_ready", message="Result is not ready", details=[])

    if not isinstance(parsed_result, dict):
        raise ConflictError(code="result_not_ready", message="Result is not ready", details=[])

    return JobResultResponse(
        job_id=job.id,
        status=job.status,
        result=parsed_result,
        request_id=request.state.request_id,
    )


@router.get(
    "/jobs/{job_id}/audit",
    response_model=JobAuditResponse,
    responses={
        404: {
            "description": "Job not found",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "job_not_found",
                            "message": "Job not found",
                            "details": [],
                        },
                        "request_id": "<request-id>",
                    }
                }
            },
        }
    },
)
def get_job_audit(request: Request, job_id: str) -> JobAuditResponse:
    """Retrieve the current job snapshot and ordered audit history for debugging/support.

    The response is sanitized for safe support use: secrets and raw incident content
    are redacted or suppressed before persistence/serialization.
    """
    retrieval_service = request.app.state.audit_retrieval_service
    result = retrieval_service.get_job_audit(job_id, request.state.request_id)
    if not result.found or result.response is None:
        raise NotFoundError(code="job_not_found", message="Job not found", details=[])
    return result.response


def _get_job_or_404(persistence_service: Any, job_id: str) -> Any:
    job = persistence_service.get_job(job_id)
    if job is None:
        raise NotFoundError(code="job_not_found", message="Job not found", details=[])
    return job


def _get_artifact_or_404(persistence_service: Any, job_id: str, artifact_type: str) -> Any:
    artifacts = persistence_service.list_artifacts(job_id=job_id, artifact_type=artifact_type)
    if not artifacts:
        raise NotFoundError(
            code="artifact_not_found",
            message=f"{artifact_type} artifact not found",
            details=[],
        )
    return artifacts[0]


def _resolve_artifact_path_or_404(file_storage: Any, relative_path: str, artifact_type: str):
    try:
        absolute_path = file_storage.resolve_stored_path(relative_path)
    except (FileNotFoundError, ValueError):
        raise NotFoundError(
            code="artifact_not_found",
            message=f"{artifact_type} artifact not found",
            details=[],
        ) from None

    if not absolute_path.exists() or not absolute_path.is_file():
        raise NotFoundError(
            code="artifact_not_found",
            message=f"{artifact_type} artifact not found",
            details=[],
        )
    return absolute_path


def _to_utc_z(value: Any) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
