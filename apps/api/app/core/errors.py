from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException


class APIError(Exception):
    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message


def error_response(request, status, code, message, headers=None):
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message,
                           "request_id": request.state.request_id, "details": {}}},
        headers=headers,
    )


def install_error_handlers(app):
    @app.exception_handler(APIError)
    async def api_error(request: Request, exc: APIError):
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return error_response(request, exc.status, exc.code, exc.message, headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Validation inputs may contain credentials; never echo the submitted body.
        return error_response(request, 422, "validation_error", "Invalid request parameters.")

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException):
        code = "not_found" if exc.status_code == 404 else "http_error"
        return error_response(request, exc.status_code, code, "Request could not be completed.", exc.headers)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError):
        return error_response(request, 503, "service_unavailable", "Database unavailable.")
