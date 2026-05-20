import re
import sqlite3
import stat
from pathlib import Path

import pytest

from attack_flow_api.config import ensure_runtime_directories
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.filesystem import LocalFileStorage
from attack_flow_api.storage.repositories import (
    ArtifactCreate,
    InputSourceCreate,
    InputSourceFileUpdate,
    JobCreate,
    JobUpdate,
    PersistenceRepository,
)
from attack_flow_api.services.persistence_service import PersistenceService


def test_database_initializes_and_creates_required_tables(tmp_path: Path):
    db_path = tmp_path / "db" / "attack-flow.db"

    initialize_database(db_path)

    assert db_path.exists()
    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    table_names = {row[0] for row in rows}
    assert "schema_migrations" in table_names
    assert "jobs" in table_names
    assert "input_sources" in table_names
    assert "artifacts" in table_names
    assert "audit_events" in table_names


def test_job_record_can_be_created_updated_and_fetched(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    input_source = repository.create_input_source(
        InputSourceCreate(id="input-1", type="text", title="Input")
    )

    created = repository.create_job(
        JobCreate(
            id="job-1",
            status="queued",
            stage="created",
            input_source_id=input_source.id,
            request_id="req-1",
        )
    )
    assert created.id == "job-1"
    assert created.status == "queued"
    assert created.stage == "created"

    updated = repository.update_job(
        "job-1", JobUpdate(status="running", stage="processing", provider_id="provider-a")
    )
    assert updated is not None
    assert updated.status == "running"
    assert updated.stage == "processing"
    assert updated.provider_id == "provider-a"

    fetched = repository.get_job("job-1")
    assert fetched is not None
    assert fetched.id == "job-1"
    assert fetched.status == "running"
    assert fetched.stage == "processing"


def test_artifact_metadata_can_be_created_and_retrieved(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    repository = PersistenceRepository(db_path)

    repository.create_job(JobCreate(id="job-1", status="queued", stage="created"))

    created_artifact = repository.create_artifact(
        ArtifactCreate(
            id="artifact-1",
            job_id="job-1",
            type="stix",
            path="artifacts/2026/01/01/abc123.json",
            size_bytes=128,
        )
    )
    assert created_artifact.id == "artifact-1"
    assert created_artifact.type == "stix"

    fetched_by_id = repository.get_artifact_by_id("artifact-1")
    assert fetched_by_id is not None
    assert fetched_by_id.path == "artifacts/2026/01/01/abc123.json"

    fetched_list = repository.list_artifacts(job_id="job-1", artifact_type="stix")
    assert len(fetched_list) == 1
    assert fetched_list[0].id == "artifact-1"


def test_configured_directories_are_created(tmp_path: Path):
    data_dir = tmp_path / "data"
    upload_dir = data_dir / "uploads"
    artifact_dir = data_dir / "artifacts"
    sqlite_path = data_dir / "sqlite" / "attack-flow.db"

    runtime_paths = {
        "data_dir": data_dir,
        "upload_dir": upload_dir,
        "artifact_dir": artifact_dir,
        "sqlite_path": sqlite_path,
    }

    ensure_runtime_directories(runtime_paths)

    assert data_dir.is_dir()
    assert upload_dir.is_dir()
    assert artifact_dir.is_dir()
    assert sqlite_path.parent.is_dir()


def test_file_storage_uses_server_generated_names(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
    )

    stored = storage.write_upload(content=b"sample", extension="txt")

    assert stored.storage_type == "upload"
    assert stored.filename.endswith(".txt")
    assert re.fullmatch(r"[0-9a-f]{32}\.txt", stored.filename) is not None
    assert "client_filename" not in stored.filename
    assert stored.absolute_path.exists()
    assert stored.relative_path.startswith("uploads/")
    assert stat.S_IMODE(stored.absolute_path.stat().st_mode) == 0o600


def test_resolve_stored_path_rejects_path_traversal(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
    )

    with pytest.raises(ValueError):
        storage.resolve_stored_path("../../etc/passwd")


def test_strict_mode_rejects_disallowed_extension(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
        strict_mode=True,
    )

    with pytest.raises(ValueError):
        storage.write_upload(content=b"x", extension="exe")


def test_non_strict_mode_maps_unknown_extension_to_bin(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
        strict_mode=False,
    )

    stored = storage.write_upload(content=b"x", extension="exe")
    assert stored.filename.endswith(".bin")


def test_storage_respects_max_file_size(tmp_path: Path):
    data_dir = tmp_path / "data"
    storage = LocalFileStorage(
        data_dir=data_dir,
        upload_dir=data_dir / "uploads",
        artifact_dir=data_dir / "artifacts",
        max_file_size_bytes=4,
    )

    with pytest.raises(ValueError):
        storage.write_upload(content=b"12345", extension="txt")


def test_resolve_canonical_text_for_job_prefers_normalized_text(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    input_source = service.create_input_source(
        InputSourceCreate(
            id="input-1",
            type="text",
            raw_text="raw",
            content_text="content",
            normalized_text="normalized",
        )
    )
    service.create_job(
        JobCreate(
            id="job-1",
            status="queued",
            stage="queued",
            input_source_id=input_source.id,
        )
    )

    assert service.resolve_canonical_text_for_job("job-1") == "normalized"


def test_update_input_source_file_persists_plaintext_extraction_fields(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    created = service.create_input_source(
        InputSourceCreate(
            id="input-plain-1",
            type="file",
            original_name="notes.txt",
            storage_path="uploads/2026/01/01/abc123.txt",
            mime_type="text/plain",
            size_bytes=12,
        )
    )

    updated = service.update_input_source_file(
        created.id,
        InputSourceFileUpdate(
            raw_text="alpha  \r\n\r\n\r\nbeta\t\n",
            normalized_text="alpha\n\nbeta",
            normalized_char_count=len("alpha\n\nbeta"),
            normalization_version="v1",
            content_text="alpha\n\nbeta",
        ),
    )

    assert updated is not None
    assert updated.raw_text == "alpha  \r\n\r\n\r\nbeta\t\n"
    assert updated.normalized_text == "alpha\n\nbeta"
    assert updated.normalized_char_count == len("alpha\n\nbeta")
    assert updated.normalization_version == "v1"
    assert updated.content_text == "alpha\n\nbeta"


def test_update_input_source_file_persists_pdf_extraction_fields(tmp_path: Path):
    db_path = tmp_path / "attack-flow.db"
    initialize_database(db_path)
    service = PersistenceService(db_path)

    created = service.create_input_source(
        InputSourceCreate(
            id="input-pdf-1",
            type="file",
            original_name="report.pdf",
            storage_path="uploads/2026/01/01/abc123.pdf",
            mime_type="application/pdf",
            size_bytes=321,
        )
    )

    updated = service.update_input_source_file(
        created.id,
        InputSourceFileUpdate(
            raw_text="Page One\r\n\r\n\r\nPage Two\n",
            normalized_text="Page One\n\nPage Two",
            normalized_char_count=len("Page One\n\nPage Two"),
            normalization_version="v1",
            content_text="Page One\n\nPage Two",
        ),
    )

    assert updated is not None
    assert updated.raw_text == "Page One\r\n\r\n\r\nPage Two\n"
    assert updated.normalized_text == "Page One\n\nPage Two"
    assert updated.normalized_char_count == len("Page One\n\nPage Two")
    assert updated.normalization_version == "v1"
    assert updated.content_text == "Page One\n\nPage Two"
