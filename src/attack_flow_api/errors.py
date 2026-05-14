import logging

from fastapi import Request
from fastapi.responses import JSONResponse

from attack_flow_api.middleware import REQUEST_ID_HEADER


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "")
    logging.getLogger("attack_flow_api.error").exception(
        "unhandled exception",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "route": request.url.path,
            "status_code": 500,
            "duration_ms": None,
        },
    )

    response = JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_server_error",
                "message": "An unexpected error occurred",
                "details": [],
            },
            "request_id": request_id,
        },
    )

    if request_id:
        response.headers[REQUEST_ID_HEADER] = request_id
    return response
