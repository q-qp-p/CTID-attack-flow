import asyncio
import logging
from uuid import uuid4

from attack_flow_api.services.persistence_service import PersistenceService


class JobWorkerService:
    def __init__(
        self,
        persistence_service: PersistenceService,
        poll_interval_seconds: float = 1.0,
    ):
        self.persistence_service = persistence_service
        self.poll_interval_seconds = poll_interval_seconds
        self.worker_id = f"worker-{uuid4()}"
        self._shutdown_event = asyncio.Event()
        self._wake_event = asyncio.Event()
        self._logger = logging.getLogger("attack_flow_api.worker")
        self._forced_failure_job_ids: set[str] = set()
        self._stage_progress = {
            "fetching": 10,
            "extracting": 25,
            "normalizing": 40,
            "ai_extraction": 60,
            "flow_building": 80,
            "exporting": 95,
        }
        self._processing_stages = (
            "extracting",
            "normalizing",
            "ai_extraction",
            "flow_building",
            "exporting",
        )

    async def run(self) -> None:
        self._logger.info("job worker started", extra={"worker_id": self.worker_id})
        try:
            while not self._shutdown_event.is_set():
                claimed_job = self.persistence_service.claim_next_queued_job(self.worker_id)
                if claimed_job is not None:
                    self._logger.info(
                        "queued job claimed",
                        extra={
                            "worker_id": self.worker_id,
                            "job_id": claimed_job.id,
                            "status": claimed_job.status,
                            "stage": claimed_job.stage,
                        },
                    )
                    await self._process_claimed_job(claimed_job.id)
                    continue

                try:
                    await asyncio.wait_for(self._wake_event.wait(), timeout=self.poll_interval_seconds)
                except TimeoutError:
                    pass
                finally:
                    self._wake_event.clear()
        except asyncio.CancelledError:
            self._logger.info("job worker cancelled", extra={"worker_id": self.worker_id})
            raise
        finally:
            self._logger.info("job worker stopped", extra={"worker_id": self.worker_id})

    def stop(self) -> None:
        self._shutdown_event.set()
        self._wake_event.set()

    def notify_new_job(self) -> None:
        self._wake_event.set()

    def force_failure_for_job(self, job_id: str) -> None:
        self._forced_failure_job_ids.add(job_id)

    async def _process_claimed_job(self, job_id: str) -> None:
        try:
            for stage in self._processing_stages:
                self._advance_stage(job_id, stage)
                await self._run_stage_hook(job_id, stage)

            self.persistence_service.mark_job_completed(job_id)
            self._logger.info(
                "job lifecycle completed",
                extra={"worker_id": self.worker_id, "job_id": job_id, "status": "completed"},
            )
        except Exception as exc:  # pragma: no cover
            self.persistence_service.mark_job_failed(
                job_id,
                error_code="worker_processing_error",
                error_message=str(exc),
            )
            self._logger.exception(
                "job lifecycle failed",
                extra={"worker_id": self.worker_id, "job_id": job_id},
            )

    def _advance_stage(self, job_id: str, stage: str) -> None:
        self.persistence_service.update_job_lifecycle(
            job_id,
            status=stage,
            stage=stage,
            progress_percent=self._stage_progress.get(stage),
            worker_id=self.worker_id,
        )

    async def _run_stage_hook(self, job_id: str, stage: str) -> None:
        if job_id in self._forced_failure_job_ids:
            self._forced_failure_job_ids.remove(job_id)
            raise RuntimeError("Forced worker failure for testing")
        normalized_text = None
        if stage == "ai_extraction":
            normalized_text = self.persistence_service.resolve_canonical_text_for_job(job_id)
        _ = (job_id, stage, normalized_text)
        await asyncio.sleep(0)
