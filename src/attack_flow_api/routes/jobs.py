import json
from dataclasses import dataclass
from datetime import UTC
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.datastructures import UploadFile

from attack_flow_api.errors import BadRequestError
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


@dataclass(slots=True)
class SubmissionPayload:
    source_type: str
    source_url: str | None = None
    content_text: str | None = None
    original_name: str | None = None
    storage_path: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    metadata: dict[str, Any] | None = None
    options: dict[str, Any] | None = None


@router.post("/jobs", response_model=JobSubmissionResponse, status_code=202)
async def submit_job(request: Request) -> JobSubmissionResponse:
    """Submit a job from JSON text/url input or multipart file upload.

    Supported modes:
    - `application/json` with `input_type=text` and non-empty `text`
    - `application/json` with `input_type=url` and non-empty `url`
    - `multipart/form-data` with required `file` and optional `metadata`/`options`

    Optional `metadata` and `options` are persisted when provided.
    """
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        payload = await _parse_json_payload(request)
        submission = _submission_from_json(payload)
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
            original_name=submission.original_name,
            storage_path=submission.storage_path,
            mime_type=submission.mime_type,
            size_bytes=submission.size_bytes,
            metadata_json=_serialize_optional_json(submission.metadata),
            options_json=_serialize_optional_json(submission.options),
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


def _submission_from_json(payload: JobSubmissionRequest) -> SubmissionPayload:
    normalized_input_type = payload.input_type.strip().lower()
    text = payload.text.strip() if isinstance(payload.text, str) else None
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
        if text:
            raise BadRequestError(
                code="conflicting_input_fields",
                message="text must not be provided when input_type is url",
                details=[],
            )

    return SubmissionPayload(
        source_type=normalized_input_type,
        source_url=url if normalized_input_type == "url" else None,
        content_text=text if normalized_input_type == "text" else None,
        metadata=payload.metadata,
        options=payload.options,
    )


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
    file_storage = request.app.state.file_storage
    extension = None
    if upload_file.filename:
        filename_parts = upload_file.filename.rsplit(".", 1)
        if len(filename_parts) == 2 and filename_parts[1]:
            extension = filename_parts[1]
    stored_file = file_storage.write_upload(file_bytes, extension=extension)

    return SubmissionPayload(
        source_type="file",
        original_name=upload_file.filename,
        mime_type=upload_file.content_type,
        size_bytes=stored_file.size_bytes,
        storage_path=stored_file.relative_path,
        metadata=metadata,
        options=options,
    )


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
                        "file": {"type": "string", "format": "binary"},
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
                            "metadata": '{"source":"upload"}',
                            "options": '{"priority":"high"}',
                        },
                    }
                },
            },
        },
    }
}
