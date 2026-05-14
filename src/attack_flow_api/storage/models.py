from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class Job:
    id: str
    status: str
    stage: str
    provider_id: str | None
    model: str | None
    input_source_id: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    error_code: str | None
    error_message: str | None
    request_id: str | None


@dataclass(slots=True)
class InputSource:
    id: str
    type: str
    original_name: str | None
    source_url: str | None
    mime_type: str | None
    size_bytes: int | None
    sha256: str | None
    title: str | None
    created_at: datetime


@dataclass(slots=True)
class Artifact:
    id: str
    job_id: str
    type: str
    path: str
    sha256: str | None
    size_bytes: int | None
    created_at: datetime


@dataclass(slots=True)
class AuditEvent:
    id: str
    job_id: str | None
    request_id: str | None
    event_type: str
    created_at: datetime
    metadata_json: str | None
