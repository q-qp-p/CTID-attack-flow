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
    result_json: str | None
    progress_percent: int | None
    started_at: datetime | None
    last_heartbeat_at: datetime | None
    worker_id: str | None
    attempt_count: int
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
    fetch_final_url: str | None
    fetch_status_code: int | None
    fetch_content_type: str | None
    fetch_size_bytes: int | None
    fetch_error_code: str | None
    fetch_error_message: str | None
    content_text: str | None
    raw_text: str | None
    normalized_text: str | None
    normalized_char_count: int | None
    was_truncated: bool | None
    normalization_version: str | None
    storage_path: str | None
    metadata_json: str | None
    options_json: str | None
    mime_type: str | None
    size_bytes: int | None
    sha256: str | None
    title: str | None
    case_id: str | None
    source_name: str | None
    stored_filename: str | None
    detected_mime_type: str | None
    file_class: str | None
    stix_json_kind: str | None
    stix_json_valid: bool | None
    stix_bundle_id: str | None
    stix_spec_version: str | None
    stix_source_type: str | None
    stix_object_count: int | None
    stix_relationship_count: int | None
    stix_attack_ref_count: int | None
    stix_summary_json: str | None
    stix_entities_json: str | None
    stix_relationships_json: str | None
    stix_attack_refs_json: str | None
    stix_provenance_json: str | None
    stix_parse_error_code: str | None
    stix_parse_error_message: str | None
    ingestion_error_code: str | None
    ingestion_error_message: str | None
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
