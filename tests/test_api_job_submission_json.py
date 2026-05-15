import sqlite3
import re
from pathlib import Path

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
