import asyncio
import sqlite3
import time
from pathlib import Path
from types import MethodType

from fastapi.testclient import TestClient

from attack_flow_api.main import create_app


def _build_client(monkeypatch, tmp_path: Path) -> TestClient:
    data_dir = tmp_path / "data"
    providers_path = tmp_path / "providers.yml"
    providers_path.write_text(
        """
providers:
  - id: default-openai
    type: openai
    enabled: true
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY
    default_model: gpt-4.1-mini
    models:
      - gpt-4.1-mini
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("APP_NAME", "attack-flow-api")
    monkeypatch.setenv("API_PREFIX", "/api/v1")
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("SQLITE_PATH", str(data_dir / "attack-flow.db"))
    monkeypatch.setenv("UPLOAD_DIR", str(data_dir / "uploads"))
    monkeypatch.setenv("ARTIFACT_DIR", str(data_dir / "artifacts"))
    monkeypatch.setenv("PROVIDERS_CONFIG_PATH", str(providers_path))

    return TestClient(create_app())


def _wait_for_status(client: TestClient, job_id: str, target_status: str, max_wait_seconds: float = 4.0):
    deadline = time.time() + max_wait_seconds
    while time.time() < deadline:
        payload = client.get(f"/api/v1/jobs/{job_id}").json()
        if payload["status"] == target_status:
            return payload
        time.sleep(0.05)
    return None


def test_worker_claims_queued_job_and_persists_claim_fields(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "claim test"},
        )
        job_id = response.json()["job_id"]

        claimed_payload = None
        for _ in range(40):
            payload = client.get(f"/api/v1/jobs/{job_id}").json()
            if payload["status"] != "queued":
                claimed_payload = payload
                break
            time.sleep(0.05)

        assert claimed_payload is not None
        assert claimed_payload["status"] in {
            "fetching",
            "extracting",
            "normalizing",
            "ai_extraction",
            "flow_building",
            "exporting",
            "completed",
        }

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT started_at, worker_id, attempt_count FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            assert row is not None
            assert row["started_at"] is not None
            assert row["worker_id"]
            assert row["attempt_count"] >= 1


def test_worker_progresses_through_expected_stages_in_order(monkeypatch, tmp_path: Path):
    expected = ["extracting", "normalizing", "ai_extraction", "flow_building", "exporting"]
    seen: list[str] = []

    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        worker.poll_interval_seconds = 0.01
        original_advance = worker._advance_stage

        def recording_advance(self, job_id: str, stage: str) -> None:
            seen.append(stage)
            return original_advance(job_id, stage)

        worker._advance_stage = MethodType(recording_advance, worker)

        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "stage order test"},
        )
        job_id = response.json()["job_id"]

        completed_payload = _wait_for_status(client, job_id, "completed")
        assert completed_payload is not None

    assert seen == expected


def test_worker_persists_intermediate_updates_and_completion(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        worker.poll_interval_seconds = 0.01
        original_hook = worker._run_stage_hook

        async def delayed_hook(self, job_id: str, stage: str) -> None:
            await asyncio.sleep(0.05)
            await original_hook(job_id, stage)

        worker._run_stage_hook = MethodType(delayed_hook, worker)

        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "persistence test"},
        )
        job_id = response.json()["job_id"]

        intermediate_seen = False
        for _ in range(40):
            with sqlite3.connect(client.app.state.sqlite_path) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(
                    "SELECT status, stage, progress_percent FROM jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
            assert row is not None
            if row["status"] in {
                "fetching",
                "extracting",
                "normalizing",
                "ai_extraction",
                "flow_building",
                "exporting",
            }:
                intermediate_seen = True
                break
            time.sleep(0.03)
        assert intermediate_seen

        completed_payload = _wait_for_status(client, job_id, "completed")
        assert completed_payload is not None
        assert completed_payload["stage"] == "completed"
        assert completed_payload["completed_at"] is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT created_at, updated_at, completed_at FROM jobs WHERE id = ?",
                (job_id,),
            ).fetchone()
            assert row is not None
            assert row["updated_at"] >= row["created_at"]
            assert row["completed_at"] is not None


def test_worker_failure_marks_failed_and_continues_with_next_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        client.app.state.job_worker.poll_interval_seconds = 0.01
        first = client.post("/api/v1/jobs", json={"input_type": "text", "text": "fail me"})
        first_job_id = first.json()["job_id"]
        client.app.state.job_worker.force_failure_for_job(first_job_id)

        second = client.post("/api/v1/jobs", json={"input_type": "text", "text": "complete me"})
        second_job_id = second.json()["job_id"]

        failed_payload = _wait_for_status(client, first_job_id, "failed")
        completed_payload = _wait_for_status(client, second_job_id, "completed")

        assert failed_payload is not None
        assert completed_payload is not None

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            failed_row = connection.execute(
                "SELECT error_code, error_message, completed_at, updated_at FROM jobs WHERE id = ?",
                (first_job_id,),
            ).fetchone()
            assert failed_row is not None
            assert failed_row["error_code"] == "worker_processing_error"
            assert failed_row["error_message"]
            assert failed_row["completed_at"] is not None
            assert failed_row["updated_at"] is not None


def test_post_jobs_remains_non_blocking_while_worker_processes(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        worker = client.app.state.job_worker
        worker.poll_interval_seconds = 0.01
        original_hook = worker._run_stage_hook

        async def delayed_hook(self, job_id: str, stage: str) -> None:
            await asyncio.sleep(0.05)
            await original_hook(job_id, stage)

        worker._run_stage_hook = MethodType(delayed_hook, worker)

        start = time.perf_counter()
        response = client.post("/api/v1/jobs", json={"input_type": "text", "text": "async check"})
        elapsed = time.perf_counter() - start
        payload = response.json()

        assert response.status_code == 202
        assert elapsed < 0.2
        status_payload = _wait_for_status(client, payload["job_id"], "completed", max_wait_seconds=5.0)
        assert status_payload is not None
        assert status_payload["request_id"]
