# Attack Flow API (Bootstrap)

Run locally with Poetry:

```bash
poetry install --with api
poetry run uvicorn attack_flow_api.main:app --reload --host 127.0.0.1 --port 8000
```

Run in Docker (API only):

```bash
docker build -f Dockerfile.api -t attack-flow-api:local .
docker run --rm -p 8000:8000 \
  -e API_HOST=0.0.0.0 \
  -e API_PORT=8000 \
  -e DATA_DIR=/var/lib/attack-flow/data \
  -e SQLITE_PATH=/var/lib/attack-flow/data/attack-flow.db \
  -e UPLOAD_DIR=/var/lib/attack-flow/data/uploads \
  -e ARTIFACT_DIR=/var/lib/attack-flow/data/artifacts \
  -v attack_flow_api_data:/var/lib/attack-flow/data \
  attack-flow-api:local
```

If you prefer a host bind mount instead of a named volume, ensure the host path is shared in Docker Desktop first.

Run with API-only Docker Compose:

```bash
cp .env.example .env
docker compose -f docker-compose.api.yml up --build
```

Run UI separately with UI-only Docker Compose:

```bash
cp .env.example .env
docker compose -f docker-compose.ui.yml up --build
```

Optional bundled proxy stack:

```bash
docker compose -f docker-compose.proxy.yml up --build
```

This optional stack proxies `/` to UI and `/api/` to API.
By default it builds UI with `VITE_API_BASE_URL_PROXY=/api/v1`.

Optional same-origin proxy example:

- See `deploy/nginx/ui-api-proxy.conf` for a minimal nginx example that serves UI static files and proxies `/api/` to the backend API.
- This is optional convenience only; separate API and UI deployment remains the default model.

For full self-hosting guidance (API/UI separate deployment, persistence, env setup, and CORS notes), see `docs/deployment-self-hosting.md`.

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

## Provider Abstraction (AFA-30)

The API now treats AI providers through a shared provider abstraction and a registry built from `PROVIDERS_CONFIG_PATH`.

- Provider configuration is loaded into internal models (`ProviderConfig`, `ProvidersConfig`) and registered once at startup.
- Provider adapters are resolved by `provider_id` via the registry instead of direct vendor-specific calls.
- Public/safe provider metadata is separated from secret-bearing configuration.
  - Public metadata includes fields such as provider id/type, enabled status, default model, and allowed models.
  - Secret-bearing fields (for example API key env var references) remain internal and are not returned from `/api/v1/providers`.
- A normalized provider error model exists for consistent error semantics across providers (auth, timeout, rate limit, unavailable, invalid response, configuration error).
- Optional provider invocation is explicitly represented:
  - no provider requested,
  - provider requested but skipped when deterministic structured input is sufficient,
  - provider requested and resolved.

Current limitations in AFA-30:

- Concrete provider vendor behavior is intentionally placeholder-only.
- Registry/adapters are for abstraction and wiring; provider validation execution and orchestration logic are handled in later tickets.
