# Self-Hosting Deployment (API and UI)

This project supports separate deployment of the API and UI.

- Default model: deploy API and UI independently.
- Optional model: use a same-origin reverse proxy (`deploy/nginx/ui-api-proxy.conf`).
- Optional bundled proxy stack: `docker-compose.proxy.yml`.

## Configuration Example

Copy `.env.example` to `.env` and update values for your environment.

```bash
cp .env.example .env
```

Key variables:

- `API_BIND_PORT`: host port for API container (`docker-compose.api.yml`)
- `UI_BIND_PORT`: host port for UI container (`docker-compose.ui.yml`)
- `VITE_API_BASE_URL`: API base URL for separate-origin/local UI deployments
- `VITE_API_BASE_URL_PROXY`: API base path for bundled proxy deployment
- `DATA_DIR`, `SQLITE_PATH`, `UPLOAD_DIR`, `ARTIFACT_DIR`: backend persistence paths

## Start API Independently

Container run:

```bash
docker build -f Dockerfile.api -t attack-flow-api:local .
docker run --rm -p 8000:8000 \
  --env-file .env \
  -v attack_flow_api_data:/var/lib/attack-flow/data \
  attack-flow-api:local
```

On macOS with Docker Desktop, a host bind mount (for example `$(pwd)/data:/var/lib/attack-flow/data`) requires that directory to be shared under Docker Desktop file sharing settings.

Compose (API-only):

```bash
docker compose -f docker-compose.api.yml up --build
```

## Start UI Independently

Container run:

```bash
docker build -f Dockerfile.ui \
  --build-arg AFB_BASE_URL=/ \
  --build-arg VITE_API_BASE_URL=http://localhost:8000/api/v1 \
  -t attack-flow-ui:local .
docker run --rm -p 8080:80 attack-flow-ui:local
```

Compose (UI-only):

```bash
docker compose -f docker-compose.ui.yml up --build
```

## Optional Bundled Proxy Stack

This is optional convenience only. Separate API and UI deployment remains the default model.

```bash
docker compose -f docker-compose.proxy.yml up --build
```

This stack includes:

- `attack-flow-api`
- `attack-flow-ui`
- `attack-flow-proxy` (nginx)

The proxy forwards:

- `/` -> UI container
- `/api/` -> API container

## How UI Reaches API

The UI API target is configured with `VITE_API_BASE_URL` at build time.

Recommended defaults by deployment model:

- Separate UI/API origins: `VITE_API_BASE_URL=http://localhost:8000/api/v1` (or `https://api.example.com/api/v1`)
- Bundled proxy stack: `VITE_API_BASE_URL_PROXY=/api/v1`

Examples:

- Local: `http://localhost:8000/api/v1`
- Separate host: `https://api.example.com/api/v1`
- Same-origin proxy path: `https://ui.example.com/api/v1`

## Backend Persistence

API persistence is volume-backed in `docker-compose.api.yml`:

- Docker named volume: `attack_flow_api_data`
- Container mount: `/var/lib/attack-flow/data`

SQLite DB and stored files survive restarts as long as the volume is retained.

## Local-Only / Internal Use

- Bind ports to private interfaces or trusted networks when possible.
- Keep `.env` local and do not commit it.
- Use least-privilege network access between UI and API.

## Internet-Exposed Use

- Terminate TLS at your edge/load balancer/reverse proxy.
- Restrict inbound access with firewall rules.
- Rotate provider credentials and keep secrets out of images and source control.

## Separate-Origin UI/API and CORS Guidance

If UI and API are hosted on different origins (scheme/host/port), browser calls require CORS to allow the UI origin.

- Current deployment package does not automatically configure CORS policy for you.
- Recommended options:
  1. Deploy with same-origin proxying (optional `deploy/nginx/ui-api-proxy.conf`), or
  2. Configure API CORS policy to explicitly allow your UI origin(s) in your deployment environment.

API CORS runtime environment variables:

- `CORS_ENABLED=true`
- `CORS_ALLOW_ORIGINS=https://ui.example.com` (comma-separated for multiple origins)
- `CORS_ALLOW_CREDENTIALS=false`
- `CORS_ALLOW_METHODS=*`
- `CORS_ALLOW_HEADERS=*`

Avoid wildcard CORS for internet-facing deployments unless you fully understand the risk.

## Troubleshooting

### Docker network not found when starting compose

If you see an error like `failed to set up container networking` or `network ... not found`, clean stale compose resources and recreate the stack:

```bash
docker compose -f docker-compose.proxy.yml down --remove-orphans
docker compose -f docker-compose.proxy.yml up --build -d
```

If the issue persists, prune unused networks and retry:

```bash
docker network prune -f
docker compose -f docker-compose.proxy.yml up --build -d
```

You can verify running services with:

```bash
docker compose -f docker-compose.proxy.yml ps
```

### Docker Desktop mount denied (macOS)

If you see an error like `mounts denied` and `path ... is not shared from the host`, Docker Desktop does not have access to that host directory.

Options:

1. Use a Docker named volume instead of a host bind mount (recommended):

```bash
docker run --rm -p 8000:8000 --env-file .env \
  -v attack_flow_api_data:/var/lib/attack-flow/data \
  attack-flow-api:local
```

2. Or add the host path in Docker Desktop:

- Docker Desktop -> Settings (Preferences) -> Resources -> File Sharing
- Add your repository path (for example `/Users/<you>/code/ctid/flow-viz-4`)
- Retry the same `docker run` or compose command
