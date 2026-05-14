from datetime import UTC, datetime

from fastapi import APIRouter, Request


router = APIRouter(tags=["health"])


@router.get("/health")
def health_check(request: Request) -> dict[str, str]:
    return {
        "status": "ok",
        "service": request.app.title,
        "version": request.app.version,
        "time": datetime.now(UTC).isoformat(),
        "request_id": request.state.request_id,
    }


@router.get("/status")
def service_status(request: Request) -> dict[str, object]:
    settings = request.app.state.settings
    providers_config = request.app.state.providers_config
    runtime_paths = request.app.state.runtime_paths

    return {
        "status": "ok",
        "environment": settings.app_env,
        "providers_configured": len(providers_config.providers),
        "storage": {
            "data_dir": str(runtime_paths["data_dir"]),
            "upload_dir": str(runtime_paths["upload_dir"]),
            "artifact_dir": str(runtime_paths["artifact_dir"]),
        },
        "request_id": request.state.request_id,
    }
