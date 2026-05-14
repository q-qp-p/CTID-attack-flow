from pathlib import Path

from attack_flow_api.storage.models import Artifact, AuditEvent, InputSource, Job
from attack_flow_api.storage.repositories import (
    ArtifactCreate,
    AuditEventCreate,
    InputSourceCreate,
    JobCreate,
    JobUpdate,
    PersistenceRepository,
)


class PersistenceService:
    def __init__(self, sqlite_path: Path):
        self.repository = PersistenceRepository(sqlite_path)

    def create_job(self, payload: JobCreate) -> Job:
        return self.repository.create_job(payload)

    def update_job(self, job_id: str, payload: JobUpdate) -> Job | None:
        return self.repository.update_job(job_id, payload)

    def get_job(self, job_id: str) -> Job | None:
        return self.repository.get_job(job_id)

    def create_input_source(self, payload: InputSourceCreate) -> InputSource:
        return self.repository.create_input_source(payload)

    def create_artifact(self, payload: ArtifactCreate) -> Artifact:
        return self.repository.create_artifact(payload)

    def get_artifact_by_id(self, artifact_id: str) -> Artifact | None:
        return self.repository.get_artifact_by_id(artifact_id)

    def list_artifacts(
        self, job_id: str | None = None, artifact_type: str | None = None
    ) -> list[Artifact]:
        return self.repository.list_artifacts(job_id=job_id, artifact_type=artifact_type)

    def create_audit_event(self, payload: AuditEventCreate) -> AuditEvent:
        return self.repository.create_audit_event(payload)

    def is_database_ready(self) -> bool:
        return self.repository.is_database_ready()

    def get_job_status_counts(self) -> dict[str, int]:
        return self.repository.get_job_status_counts()
