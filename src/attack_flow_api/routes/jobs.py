import json
from dataclasses import dataclass
from datetime import UTC
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.datastructures import UploadFile

from attack_flow_api.errors import BadRequestError, ConflictError, NotFoundError
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

    Submission is non-blocking: this endpoint queues work and returns `202 Accepted`.
    An in-process worker advances queued jobs asynchronously through lifecycle stages.
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
