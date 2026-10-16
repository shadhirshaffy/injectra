import logging
from uuid import uuid4

from fastapi import FastAPI, Request

from app.core.errors import error_response, install_error_handlers

app = FastAPI(
    title="Injectra API",
    description="AI Security & Prompt Injection Defense Gateway",
    version="0.1.0",
)


@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = str(uuid4())
    try:
        response = await call_next(request)
    except Exception:
        # Avoid logging exception strings that can contain SQL parameters or keys.
        logging.getLogger(__name__).error("Unhandled request failure: %s", request.state.request_id)
        response = error_response(request, 500, "internal_error", "An internal error occurred.")
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    return response


install_error_handlers(app)


@app.get("/api/v1/health")
def health_check():
    return {"status": "ok", "service": "injectra-api", "version": "0.1.0"}


# Import after app setup; database credentials are required for management routes.
from app.api.management import router  # noqa: E402

app.include_router(router)

from app.api.policies import router as policy_router  # noqa: E402

app.include_router(policy_router)

from app.api.security_events import router as event_router  # noqa: E402

app.include_router(event_router)
