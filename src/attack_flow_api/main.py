from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI

from attack_flow_api.config import (
    AppSettings,
    ProvidersConfig,
    ensure_runtime_directories,
    load_providers_config,
    load_settings,
    resolve_runtime_paths,
)
from attack_flow_api.errors import unhandled_exception_handler
from attack_flow_api.logging_utils import setup_logging
from attack_flow_api.middleware import RequestContextMiddleware
from attack_flow_api.routes.health import router as health_router
from attack_flow_api.services.persistence_service import PersistenceService
from attack_flow_api.storage.database import initialize_database
from attack_flow_api.storage.filesystem import LocalFileStorage


def create_api_router() -> APIRouter:
    router = APIRouter()
    router.include_router(health_router)
    return router


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = load_settings()
    setup_logging(settings.log_level)
    providers_config = load_providers_config(settings.providers_config_path)
    runtime_paths = resolve_runtime_paths(settings)
    ensure_runtime_directories(runtime_paths)
    initialize_database(settings.sqlite_path)
    persistence_service = PersistenceService(settings.sqlite_path)
    file_storage = LocalFileStorage(
        data_dir=settings.data_dir,
        upload_dir=settings.upload_dir,
        artifact_dir=settings.artifact_dir,
        strict_mode=settings.file_storage_strict_mode,
        max_file_size_bytes=settings.file_storage_max_bytes,
    )

    app.state.settings = settings
    app.state.providers_config = providers_config
    app.state.runtime_paths = runtime_paths
    app.state.sqlite_path = settings.sqlite_path
    app.state.persistence_service = persistence_service
    app.state.file_storage = file_storage
    yield


def create_app() -> FastAPI:
    settings = load_settings()
    app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
    app.add_middleware(RequestContextMiddleware)
    app.add_exception_handler(Exception, unhandled_exception_handler)
    app.include_router(create_api_router(), prefix=settings.api_prefix)
    return app


app = create_app()


def get_app_settings(app_instance: FastAPI) -> AppSettings:
    return app_instance.state.settings


def get_providers_config(app_instance: FastAPI) -> ProvidersConfig:
    return app_instance.state.providers_config
