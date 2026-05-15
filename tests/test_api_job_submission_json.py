import sqlite3
import re
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from attack_flow_api.main import create_app
from attack_flow_api.storage.repositories import ArtifactCreate, JobUpdate


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


def _assert_common_accepted_response(payload: dict[str, str]) -> None:
    assert payload["job_id"]
    assert payload["status"] == "queued"
    assert payload["poll_url"] == f"/api/v1/jobs/{payload['job_id']}"
    assert payload["request_id"]


def test_submit_job_text_returns_202_and_persists_records(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "investigation content",
                "metadata": {"source": "unit-test"},
                "options": {"priority": "normal"},
            },
        )

        payload = response.json()
        assert response.status_code == 202
        _assert_common_accepted_response(payload)
        assert payload["submitted_at"]

        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None
        assert job_row["status"] == "queued"

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["type"] == "text"
        assert input_row["content_text"] == "investigation content"
        assert input_row["source_url"] is None
        assert input_row["metadata_json"] == '{"source": "unit-test"}'
        assert input_row["options_json"] == '{"priority": "normal"}'


def test_submit_job_url_returns_202_and_persists_url(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "url", "url": "https://example.com/report"},
        )

        payload = response.json()
        assert response.status_code == 202
        _assert_common_accepted_response(payload)

        sqlite_path = client.app.state.sqlite_path

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None
        assert job_row["status"] == "queued"

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["type"] == "url"
        assert input_row["source_url"] == "https://example.com/report"
        assert input_row["content_text"] is None


def test_submit_job_conflicting_shape_returns_structured_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "hello", "url": "https://example.com"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "conflicting_input_fields"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_unsupported_input_type_returns_structured_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "file", "url": "https://example.com"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_input_type"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_missing_supported_input_returns_structured_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "   "},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_text_input"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_submit_job_invalid_json_shape_stays_422(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post("/api/v1/jobs", json={"input_type": "text", "text": 123})

    assert response.status_code == 422


def test_submit_job_multipart_file_returns_202_and_persists_file_metadata(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"hello", "text/plain")},
            data={"metadata": '{"source":"upload"}', "options": '{"priority":"high"}'},
        )

        payload = response.json()
        assert response.status_code == 202
        _assert_common_accepted_response(payload)

        sqlite_path = client.app.state.sqlite_path
        data_dir = client.app.state.settings.data_dir

    with sqlite3.connect(sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (payload["job_id"],)).fetchone()
        assert job_row is not None

        input_row = connection.execute(
            "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
        ).fetchone()
        assert input_row is not None
        assert input_row["type"] == "file"
        assert input_row["original_name"] == "evidence.txt"
        assert input_row["mime_type"] == "text/plain"
        assert input_row["size_bytes"] == 5
        assert input_row["storage_path"].startswith("uploads/")
        assert input_row["metadata_json"] == '{"source": "upload"}'
        assert input_row["options_json"] == '{"priority": "high"}'

    stored_path = data_dir / input_row["storage_path"]
    assert stored_path.exists()
    assert stored_path.read_bytes() == b"hello"
    assert re.fullmatch(r"[0-9a-f]{32}\.txt", stored_path.name) is not None


def test_submit_job_multipart_missing_file_returns_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"metadata": (None, '{"source":"upload"}')},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "missing_file"


def test_submit_job_multipart_invalid_metadata_returns_400(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"hello", "text/plain")},
            data={"metadata": "not-json"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "invalid_json_field"


def test_submit_job_multipart_rejects_non_file_input_fields(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"hello", "text/plain")},
            data={"input_type": "text", "text": "hello"},
        )

    payload = response.json()
    assert response.status_code == 400
    assert payload["error"]["code"] == "conflicting_input_fields"


def test_get_job_status_returns_200_with_job_state(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={
                "input_type": "text",
                "text": "investigation content",
                "metadata": {"source": "manual"},
            },
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/jobs/{job_id}")

    payload = response.json()
    assert response.status_code == 200
    assert payload["job_id"] == job_id
    assert payload["status"] == "queued"
    assert payload["stage"] == "queued"
    assert payload["created_at"]
    assert payload["updated_at"]
    assert payload["completed_at"] is None
    assert payload["input"]["input_type"] == "text"
    assert payload["input"]["original_filename"] is None
    assert payload["request_id"]


def test_get_job_status_returns_structured_404_when_missing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/jobs/missing-job")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_delete_job_returns_200_and_removes_related_records_and_files(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            files={"file": ("evidence.txt", b"hello", "text/plain")},
        )
        job_id = create_response.json()["job_id"]

        with sqlite3.connect(client.app.state.sqlite_path) as connection:
            connection.row_factory = sqlite3.Row
            job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            assert job_row is not None
            input_row = connection.execute(
                "SELECT * FROM input_sources WHERE id = ?", (job_row["input_source_id"],)
            ).fetchone()
            assert input_row is not None

        artifact_file = client.app.state.file_storage.write_artifact(b"{}", extension="json")
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
            )
        )

        upload_path = client.app.state.settings.data_dir / input_row["storage_path"]
        assert upload_path.exists()
        assert artifact_file.absolute_path.exists()

        response = client.delete(f"/api/v1/jobs/{job_id}")

    payload = response.json()
    assert response.status_code == 200
    assert payload == {"job_id": job_id, "deleted": True, "request_id": payload["request_id"]}
    assert payload["request_id"]

    with sqlite3.connect(client.app.state.sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        assert connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone() is None
        assert (
            connection.execute("SELECT * FROM input_sources WHERE id = ?", (input_row["id"],)).fetchone()
            is None
        )
        assert connection.execute("SELECT * FROM artifacts WHERE job_id = ?", (job_id,)).fetchone() is None

    assert not upload_path.exists()
    assert not artifact_file.absolute_path.exists()


def test_delete_job_returns_structured_404_when_missing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.delete("/api/v1/jobs/missing-job")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_download_job_stix_artifact_returns_json_file(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        artifact_file = client.app.state.file_storage.write_artifact(
            b'{"type":"bundle","id":"bundle--stix"}',
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="stix",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
            )
        )

        response = client.get(f"/api/v1/jobs/{job_id}/artifacts/stix")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"].endswith(f'filename="{job_id}-stix.json"')
    assert response.headers.get("x-request-id")
    assert response.json()["id"] == "bundle--stix"


def test_download_job_afb_artifact_returns_json_file(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "url", "url": "https://example.com/report"},
        )
        job_id = create_response.json()["job_id"]

        artifact_file = client.app.state.file_storage.write_artifact(
            b'{"format":"afb","version":"1"}',
            extension="json",
        )
        client.app.state.persistence_service.create_artifact(
            payload=ArtifactCreate(
                id=str(uuid4()),
                job_id=job_id,
                type="afb",
                path=artifact_file.relative_path,
                size_bytes=artifact_file.size_bytes,
            )
        )

        response = client.get(f"/api/v1/jobs/{job_id}/artifacts/afb")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"].endswith(f'filename="{job_id}-afb.afb"')
    assert response.headers.get("x-request-id")
    assert response.json()["format"] == "afb"


def test_download_job_artifact_returns_structured_404_for_missing_job(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/jobs/missing-job/artifacts/stix")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_download_job_artifact_returns_structured_404_for_missing_artifact(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/jobs/{job_id}/artifacts/stix")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "artifact_not_found"
    assert payload["error"]["message"] == "stix artifact not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_get_job_result_returns_structured_404_when_job_missing(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        response = client.get("/api/v1/jobs/missing-job/result")

    payload = response.json()
    assert response.status_code == 404
    assert payload["error"]["code"] == "job_not_found"
    assert payload["error"]["message"] == "Job not found"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_get_job_result_returns_structured_409_when_not_ready(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "text", "text": "investigation content"},
        )
        job_id = create_response.json()["job_id"]

        response = client.get(f"/api/v1/jobs/{job_id}/result")

    payload = response.json()
    assert response.status_code == 409
    assert payload["error"]["code"] == "result_not_ready"
    assert payload["error"]["message"] == "Result is not ready"
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_get_job_result_returns_200_when_structured_result_exists(monkeypatch, tmp_path: Path):
    with _build_client(monkeypatch, tmp_path) as client:
        create_response = client.post(
            "/api/v1/jobs",
            json={"input_type": "url", "url": "https://example.com/report"},
        )
        job_id = create_response.json()["job_id"]

        client.app.state.persistence_service.update_job(
            job_id,
            JobUpdate(
                result_json=(
                    '{"summary":"ready","techniques":["T1059"],'
                    '"artifacts":{"stix":true,"afb":false}}'
                )
            ),
        )

        response = client.get(f"/api/v1/jobs/{job_id}/result")

    payload = response.json()
    assert response.status_code == 200
    assert payload["job_id"] == job_id
    assert payload["status"] == "queued"
    assert payload["result"]["summary"] == "ready"
    assert payload["result"]["techniques"] == ["T1059"]
    assert payload["result"]["artifacts"] == {"stix": True, "afb": False}
    assert payload["request_id"]
