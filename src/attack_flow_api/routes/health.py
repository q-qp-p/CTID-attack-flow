from datetime import UTC, datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from attack_flow_api.config import ProviderPublicMetadata
from attack_flow_api.services.status_service import StatusService


router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    time: str
    request_id: str


class ProvidersSummary(BaseModel):
    configured_count: int


class QueueSummary(BaseModel):
    active_jobs: int
    pending_jobs: int


class StatusResponse(BaseModel):
    status: str
    database: str
    storage: str
    providers: ProvidersSummary
    queue: QueueSummary
    request_id: str


class ProviderPublic(BaseModel):
    id: str
    type: str
    enabled: bool
    default_model: str | None = None
    models: list[str] = Field(default_factory=list)


class ProvidersResponse(BaseModel):
    providers: list[ProviderPublic]
    request_id: str


@router.get("/health", response_model=HealthResponse)
def health_check(request: Request) -> HealthResponse:
    return HealthResponse(
        status="ok",
        service=request.app.title,
        version=request.app.version,
        time=datetime.now(UTC).isoformat(),
        request_id=request.state.request_id,
    )


@router.get("/status", response_model=StatusResponse)
def service_status(request: Request) -> StatusResponse:
    """Return lightweight operational status, including configured provider count.

    Provider information exposed here is intentionally non-secret and reflects
    registry-driven provider configuration loaded at startup.
    """
    persistence_service = request.app.state.persistence_service
    providers_config = request.app.state.providers_config
    runtime_paths = request.app.state.runtime_paths
    status_service = StatusService(persistence_service)

    database_status = status_service.database_status()
    storage_status = status_service.storage_status(runtime_paths)
    queue_counts = status_service.queue_counts()

    overall_status = "ok"
    if database_status != "ok" or storage_status != "ok":
        overall_status = "degraded"

    return StatusResponse(
        status=overall_status,
        database=database_status,
        storage=storage_status,
        providers=ProvidersSummary(configured_count=len(providers_config.providers)),
        queue=QueueSummary(
            active_jobs=queue_counts["active_jobs"], pending_jobs=queue_counts["pending_jobs"]
        ),
        request_id=request.state.request_id,
    )


@router.get("/providers", response_model=ProvidersResponse)
def list_providers(request: Request) -> ProvidersResponse:
    """Return safe/public provider metadata only.

    This endpoint intentionally excludes secret-bearing provider configuration
    (for example API key environment variable references).
    """
    providers_config = request.app.state.providers_config
    providers = [
        _to_provider_public(provider)
        for provider in providers_config.list_public_metadata()
    ]

    return ProvidersResponse(providers=providers, request_id=request.state.request_id)


def _to_provider_public(provider: ProviderPublicMetadata) -> ProviderPublic:
    return ProviderPublic(
        id=provider.provider_id,
        type=provider.provider_type,
        enabled=provider.enabled,
        default_model=provider.default_model,
        models=provider.allowed_models,
    )
