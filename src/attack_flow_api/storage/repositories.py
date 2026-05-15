from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from attack_flow_api.storage.database import create_connection
from attack_flow_api.storage.models import Artifact, AuditEvent, InputSource, Job


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _require_datetime(value: str | None, field_name: str) -> datetime:
    parsed = _parse_datetime(value)
    if parsed is None:
        raise ValueError(f"Missing required datetime field: {field_name}")
    return parsed


@dataclass(slots=True)
class JobCreate:
    id: str
    status: str
    stage: str
    provider_id: str | None = None
    model: str | None = None
    input_source_id: str | None = None
    request_id: str | None = None


@dataclass(slots=True)
class JobUpdate:
    status: str | None = None
    stage: str | None = None
    provider_id: str | None = None
    model: str | None = None
    input_source_id: str | None = None
    completed_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    request_id: str | None = None


@dataclass(slots=True)
class InputSourceCreate:
    id: str
    type: str
    original_name: str | None = None
    source_url: str | None = None
    content_text: str | None = None
    storage_path: str | None = None
    metadata_json: str | None = None
    options_json: str | None = None
    mime_type: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    title: str | None = None


@dataclass(slots=True)
class ArtifactCreate:
    id: str
    job_id: str
    type: str
    path: str
    sha256: str | None = None
    size_bytes: int | None = None


@dataclass(slots=True)
class AuditEventCreate:
    id: str
    event_type: str
    job_id: str | None = None
    request_id: str | None = None
    metadata_json: str | None = None


class PersistenceRepository:
    def __init__(self, sqlite_path: Path):
        self.sqlite_path = sqlite_path

    def create_job(self, payload: JobCreate) -> Job:
        now = _utcnow_iso()
        with create_connection(self.sqlite_path) as connection:
            connection.execute(
                """
                INSERT INTO jobs (
                    id, status, stage, provider_id, model, input_source_id,
                    created_at, updated_at, request_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    payload.status,
                    payload.stage,
                    payload.provider_id,
                    payload.model,
                    payload.input_source_id,
                    now,
                    now,
                    payload.request_id,
                ),
            )
        created = self.get_job(payload.id)
        if created is None:
            raise RuntimeError("Failed to create job")
        return created

    def update_job(self, job_id: str, payload: JobUpdate) -> Job | None:
        updates: dict[str, object] = {}
        for field_name in (
            "status",
            "stage",
            "provider_id",
            "model",
            "input_source_id",
            "error_code",
            "error_message",
            "request_id",
        ):
            value = getattr(payload, field_name)
            if value is not None:
                updates[field_name] = value

        if payload.completed_at is not None:
            updates["completed_at"] = payload.completed_at.isoformat().replace("+00:00", "Z")

        updates["updated_at"] = _utcnow_iso()
        set_clause = ", ".join([f"{key} = ?" for key in updates])
        params = list(updates.values()) + [job_id]

        with create_connection(self.sqlite_path) as connection:
            result = connection.execute(
                f"UPDATE jobs SET {set_clause} WHERE id = ?",  # noqa: S608
                params,
            )
            if result.rowcount == 0:
                return None

        return self.get_job(job_id)

    def get_job(self, job_id: str) -> Job | None:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        return Job(
            id=row["id"],
            status=row["status"],
            stage=row["stage"],
            provider_id=row["provider_id"],
            model=row["model"],
            input_source_id=row["input_source_id"],
            created_at=_require_datetime(row["created_at"], "created_at"),
            updated_at=_require_datetime(row["updated_at"], "updated_at"),
            completed_at=_parse_datetime(row["completed_at"]),
            error_code=row["error_code"],
            error_message=row["error_message"],
            request_id=row["request_id"],
        )

    def create_input_source(self, payload: InputSourceCreate) -> InputSource:
        now = _utcnow_iso()
        with create_connection(self.sqlite_path) as connection:
            connection.execute(
                """
                INSERT INTO input_sources (
                    id, type, original_name, source_url, content_text, storage_path, metadata_json,
                    options_json, mime_type,
                    size_bytes, sha256, title, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    payload.type,
                    payload.original_name,
                    payload.source_url,
                    payload.content_text,
                    payload.storage_path,
                    payload.metadata_json,
                    payload.options_json,
                    payload.mime_type,
                    payload.size_bytes,
                    payload.sha256,
                    payload.title,
                    now,
                ),
            )
        return self.get_input_source(payload.id)

    def get_input_source(self, input_source_id: str) -> InputSource | None:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (input_source_id,)
            ).fetchone()
        if row is None:
            return None
        return InputSource(
            id=row["id"],
            type=row["type"],
            original_name=row["original_name"],
            source_url=row["source_url"],
            content_text=row["content_text"],
            storage_path=row["storage_path"],
            metadata_json=row["metadata_json"],
            options_json=row["options_json"],
            mime_type=row["mime_type"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
            title=row["title"],
            created_at=_require_datetime(row["created_at"], "created_at"),
        )

    def create_artifact(self, payload: ArtifactCreate) -> Artifact:
        now = _utcnow_iso()
        with create_connection(self.sqlite_path) as connection:
            connection.execute(
                """
                INSERT INTO artifacts (id, job_id, type, path, sha256, size_bytes, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    payload.job_id,
                    payload.type,
                    payload.path,
                    payload.sha256,
                    payload.size_bytes,
                    now,
                ),
            )
        created = self.get_artifact_by_id(payload.id)
        if created is None:
            raise RuntimeError("Failed to create artifact")
        return created

    def get_artifact_by_id(self, artifact_id: str) -> Artifact | None:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
            ).fetchone()
        if row is None:
            return None
        return Artifact(
            id=row["id"],
            job_id=row["job_id"],
            type=row["type"],
            path=row["path"],
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            created_at=_require_datetime(row["created_at"], "created_at"),
        )

    def list_artifacts(self, job_id: str | None = None, artifact_type: str | None = None) -> list[Artifact]:
        query = "SELECT * FROM artifacts"
        clauses: list[str] = []
        params: list[object] = []

        if job_id is not None:
            clauses.append("job_id = ?")
            params.append(job_id)
        if artifact_type is not None:
            clauses.append("type = ?")
            params.append(artifact_type)
        if clauses:
            query = f"{query} WHERE {' AND '.join(clauses)}"
        query = f"{query} ORDER BY created_at ASC"

        with create_connection(self.sqlite_path) as connection:
            rows = connection.execute(query, params).fetchall()

        return [
            Artifact(
                id=row["id"],
                job_id=row["job_id"],
                type=row["type"],
                path=row["path"],
                sha256=row["sha256"],
                size_bytes=row["size_bytes"],
                created_at=_require_datetime(row["created_at"], "created_at"),
            )
            for row in rows
        ]

    def create_audit_event(self, payload: AuditEventCreate) -> AuditEvent:
        now = _utcnow_iso()
        with create_connection(self.sqlite_path) as connection:
            connection.execute(
                """
                INSERT INTO audit_events (id, job_id, request_id, event_type, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.id,
                    payload.job_id,
                    payload.request_id,
                    payload.event_type,
                    now,
                    payload.metadata_json,
                ),
            )

        with create_connection(self.sqlite_path) as connection:
            row = connection.execute("SELECT * FROM audit_events WHERE id = ?", (payload.id,)).fetchone()

        if row is None:
            raise RuntimeError("Failed to create audit event")

        return AuditEvent(
            id=row["id"],
            job_id=row["job_id"],
            request_id=row["request_id"],
            event_type=row["event_type"],
            created_at=_require_datetime(row["created_at"], "created_at"),
            metadata_json=row["metadata_json"],
        )

    def is_database_ready(self) -> bool:
        with create_connection(self.sqlite_path) as connection:
            row = connection.execute("SELECT 1 AS ready").fetchone()
        return bool(row is not None and row["ready"] == 1)

    def get_job_status_counts(self) -> dict[str, int]:
        with create_connection(self.sqlite_path) as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM jobs GROUP BY status"
            ).fetchall()

        counts: dict[str, int] = {}
        for row in rows:
            status = row["status"]
            if status is None:
                continue
            counts[str(status)] = int(row["count"])
        return counts
