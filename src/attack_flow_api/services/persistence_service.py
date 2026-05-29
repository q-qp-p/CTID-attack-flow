import json
from pathlib import Path

from pydantic import BaseModel

from attack_flow_api.storage.models import Artifact, AuditEvent, InputSource, Job
from attack_flow_api.storage.repositories import (
    ArtifactCreate,
    AuditEventCreate,
    JobCanonicalFlowUpdate,
    InputSourceCreate,
    InputSourceFileUpdate,
    InputSourceFetchUpdate,
    InputSourceNormalizedUpdate,
    InputSourceStixUpdate,
    InputSourceTextUpdate,
    JobCreate,
    JobExtractionUpdate,
    JobFusionUpdate,
    JobUpdate,
    PersistenceRepository,
)
from attack_flow_api.services.afb_fusion_assembler import FusedOutputCandidate
from attack_flow_api.services.canonical_flow_contracts import CanonicalFlowOutput


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

    def get_input_source(self, input_source_id: str) -> InputSource | None:
        return self.repository.get_input_source(input_source_id)

    def resolve_canonical_text_for_job(self, job_id: str) -> str | None:
        normalized_package = self.resolve_normalized_package_for_job(job_id)
        if normalized_package is not None:
            normalized_text = normalized_package.get("normalized_text")
            if isinstance(normalized_text, str):
                return normalized_text

        input_source = self._resolve_input_source_for_job(job_id)
        return self.resolve_canonical_text_for_input_source(input_source)

    def resolve_canonical_text_for_input_source(self, input_source: InputSource | None) -> str | None:
        if input_source is None:
            return None
        if input_source.type not in {"text", "url"}:
            return None

        if input_source.normalized_text is not None:
            return input_source.normalized_text
        if input_source.content_text is not None:
            return input_source.content_text
        return input_source.raw_text

    def resolve_normalized_package_for_job(self, job_id: str) -> dict[str, object] | None:
        input_source = self._resolve_input_source_for_job(job_id)
        return self.resolve_normalized_package_for_input_source(input_source)

    def resolve_normalized_package_for_input_source(
        self, input_source: InputSource | None
    ) -> dict[str, object] | None:
        if input_source is None or input_source.normalized_package_json is None:
            return None
        try:
            parsed = json.loads(input_source.normalized_package_json)
        except json.JSONDecodeError:
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    def _resolve_input_source_for_job(self, job_id: str) -> InputSource | None:
        job = self.get_job(job_id)
        if job is None or job.input_source_id is None:
            return None
        return self.get_input_source(job.input_source_id)

    def update_input_source_text(
        self, input_source_id: str, payload: InputSourceTextUpdate
    ) -> InputSource | None:
        return self.repository.update_input_source_text(input_source_id, payload)

    def update_input_source_fetch(
        self,
        input_source_id: str,
        payload: InputSourceFetchUpdate,
    ) -> InputSource | None:
        return self.repository.update_input_source_fetch(input_source_id, payload)

    def update_input_source_file(
        self,
        input_source_id: str,
        payload: InputSourceFileUpdate,
    ) -> InputSource | None:
        return self.repository.update_input_source_file(input_source_id, payload)

    def update_input_source_stix(
        self,
        input_source_id: str,
        payload: InputSourceStixUpdate,
    ) -> InputSource | None:
        return self.repository.update_input_source_stix(input_source_id, payload)

    def update_input_source_normalized(
        self,
        input_source_id: str,
        payload: InputSourceNormalizedUpdate,
    ) -> InputSource | None:
        return self.repository.update_input_source_normalized(input_source_id, payload)

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

    def delete_artifacts_for_job(self, job_id: str) -> int:
        return self.repository.delete_artifacts_for_job(job_id)

    def delete_job(self, job_id: str) -> bool:
        return self.repository.delete_job(job_id)

    def count_jobs_by_input_source(self, input_source_id: str) -> int:
        return self.repository.count_jobs_by_input_source(input_source_id)

    def delete_input_source(self, input_source_id: str) -> bool:
        return self.repository.delete_input_source(input_source_id)

    def claim_next_queued_job(self, worker_id: str) -> Job | None:
        return self.repository.claim_next_queued_job(worker_id)

    def update_job_lifecycle(
        self,
        job_id: str,
        *,
        status: str,
        stage: str,
        progress_percent: int | None = None,
        worker_id: str | None = None,
    ) -> Job | None:
        return self.repository.update_job_lifecycle(
            job_id,
            status=status,
            stage=stage,
            progress_percent=progress_percent,
            worker_id=worker_id,
        )

    def update_job_extraction(self, job_id: str, payload: JobExtractionUpdate) -> Job | None:
        return self.repository.update_job_extraction(job_id, payload)

    def update_job_fusion(self, job_id: str, payload: JobFusionUpdate) -> Job | None:
        return self.repository.update_job_fusion(job_id, payload)

    def update_job_canonical_flow(self, job_id: str, payload: JobCanonicalFlowUpdate) -> Job | None:
        return self.repository.update_job_canonical_flow(job_id, payload)

    def persist_fused_output_candidate(self, job_id: str, payload: FusedOutputCandidate) -> Job | None:
        return self.update_job_fusion(
            job_id,
            JobFusionUpdate(
                fusion_result_json=payload.model_dump_json(),
                fusion_validation_state=payload.fusion_validation_state,
                fusion_provenance_json=_json_dumps(payload.provenance),
                fusion_conflicts_json=_json_dumps_model_list(payload.conflicts),
                fusion_attack_refs_json=_json_dumps_model_list(payload.attack_refs),
                fusion_entities_json=_json_dumps_model_list(payload.entities),
                fusion_relationships_json=_json_dumps_model_list(payload.relationships),
            ),
        )

    def persist_canonical_flow_output(self, job_id: str, payload: CanonicalFlowOutput) -> Job | None:
        return self.update_job_canonical_flow(
            job_id,
            JobCanonicalFlowUpdate(
                canonical_flow_json=payload.model_dump_json(),
                canonical_flow_validation_state=payload.validation_state,
                canonical_flow_provenance_json=_json_dumps(payload.provenance),
                canonical_flow_conflicts_json=_json_dumps_model_list(payload.conflicts),
                canonical_flow_validation_errors_json=_json_dumps_model_list(payload.validation_errors),
            ),
        )

    def mark_job_completed(self, job_id: str) -> Job | None:
        return self.repository.mark_job_completed(job_id)

    def mark_job_failed(self, job_id: str, error_code: str, error_message: str) -> Job | None:
        return self.repository.mark_job_failed(job_id, error_code=error_code, error_message=error_message)


def _json_dumps(payload: object) -> str:
    return json.dumps(payload)


def _json_dumps_model_list(items: list[BaseModel]) -> str:
    return json.dumps([item.model_dump(mode="json") for item in items])
