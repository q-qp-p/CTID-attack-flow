# Attack Flow API (Bootstrap)

Run locally with Poetry:

```bash
poetry install --with api
poetry run uvicorn attack_flow_api.main:app --reload --host 127.0.0.1 --port 8000
```

On startup, the API initializes SQLite automatically at `SQLITE_PATH` (default: `data/attack-flow.db`).
It also ensures local storage directories exist for uploads, artifacts, and normalized content under `DATA_DIR`.

Quick check:

```bash
curl -s http://127.0.0.1:8000/api/v1/health
curl -s http://127.0.0.1:8000/api/v1/status
```

Example environment configuration:

```bash
export APP_NAME="attack-flow-api"
export APP_ENV="development"
export API_HOST="127.0.0.1"
export API_PORT="8000"
export API_PREFIX="/api/v1"
export LOG_LEVEL="INFO"
export DATA_DIR="data"
export SQLITE_PATH="data/attack-flow.db"
export UPLOAD_DIR="data/uploads"
export ARTIFACT_DIR="data/artifacts"
export FILE_STORAGE_STRICT_MODE="true"
export FILE_STORAGE_MAX_BYTES="10485760"
export PROVIDERS_CONFIG_PATH="config/providers.yml"
```

Optional environment variables:

- `APP_NAME`
- `APP_ENV`
- `API_HOST`
- `API_PORT`
- `API_PREFIX`
- `LOG_LEVEL`
- `DATA_DIR`
- `SQLITE_PATH`
- `UPLOAD_DIR`
- `ARTIFACT_DIR`
- `FILE_STORAGE_STRICT_MODE`
- `FILE_STORAGE_MAX_BYTES`
- `PROVIDERS_CONFIG_PATH`
