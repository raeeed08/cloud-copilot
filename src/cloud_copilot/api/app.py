"""FastAPI application factory."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from cloud_copilot import __version__
from cloud_copilot.api.routes.v1 import router as v1
from cloud_copilot.api.security import RateLimiter
from cloud_copilot.config import Settings, get_settings
from cloud_copilot.llm.gateway import LLMGateway
from cloud_copilot.log import configure_logging, get_logger
from cloud_copilot.service import CopilotService, ScanInProgressError

log = get_logger(__name__)
HTTP_REQUESTS = Counter("copilot_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_LATENCY = Histogram("copilot_http_request_seconds", "HTTP latency", ["method", "route"])
STATIC_DIR = Path(__file__).resolve().parent.parent / "web"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors 'none'"
    ),
}


def _setup_tracing(app: FastAPI, settings: Settings) -> None:
    if not settings.otel_exporter_otlp_endpoint:
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.warning("otel_not_installed", hint="pip install 'cloud-copilot[otel]'")
        return
    provider = TracerProvider(
        resource=Resource.create({"service.name": "cloud-copilot", "service.version": __version__})
    )
    provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{settings.otel_exporter_otlp_endpoint.rstrip('/')}/v1/traces"))
    )
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")


def create_app(settings: Settings | None = None, service: CopilotService | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.log_json)
    if settings.environment == "prod" and not settings.auth_enabled:
        raise RuntimeError("API_KEYS must be set when ENVIRONMENT=prod")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        log.info(
            "startup",
            version=__version__,
            demo=settings.demo_mode,
            auth=settings.auth_enabled,
            llm=LLMGateway(settings).available,
        )
        if settings.scan_on_startup and app.state.service.latest() is None:
            with suppress(ScanInProgressError):
                app.state.service.start_scan(trigger="startup")
        yield
        app.state.service._executor.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(
        title="Cloud Copilot API",
        version=__version__,
        description="Multi-cloud security & cost posture: rule engine, findings, compliance, RAG copilot.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = settings
    app.state.service = service or CopilotService(settings)
    app.state.limiter = RateLimiter()

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=["*"],
            allow_headers=["*"],
            allow_credentials=False,
        )

    @app.middleware("http")
    async def observability(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        structlog.contextvars.bind_contextvars(request_id=request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception("unhandled_error", path=request.url.path)
            response = JSONResponse({"detail": "internal error", "request_id": request_id}, status_code=500)
        route = getattr(request.scope.get("route"), "path", "unmatched")
        elapsed = time.perf_counter() - started
        HTTP_REQUESTS.labels(request.method, route, str(response.status_code)).inc()
        HTTP_LATENCY.labels(request.method, route).observe(elapsed)
        response.headers["X-Request-ID"] = request_id
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if route not in ("/healthz", "/readyz", "/metrics"):
            log.info(
                "http_request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                ms=int(elapsed * 1000),
            )
        structlog.contextvars.clear_contextvars()
        return response

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> JSONResponse:
        try:
            app.state.service.db.ping()
        except Exception as exc:
            return JSONResponse({"status": "unready", "db": type(exc).__name__}, status_code=503)
        return JSONResponse({"status": "ready"})

    @app.get("/metrics", include_in_schema=False)
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/api/v1/info", tags=["meta"])
    def info() -> dict[str, object]:
        return {
            "version": __version__,
            "demo_mode": settings.demo_mode,
            "auth": settings.auth_enabled,
            "llm": LLMGateway(settings).available,
            "providers": settings.providers,
            "rag_mode": "hybrid" if settings.embeddings_base_url else "bm25",
        }

    app.include_router(v1)
    _setup_tracing(app, settings)

    if (STATIC_DIR / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str) -> Response:
            if path.startswith("api/"):
                return JSONResponse({"detail": "not found"}, status_code=404)
            candidate = (STATIC_DIR / path).resolve()
            if path and candidate.is_file() and STATIC_DIR in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(STATIC_DIR / "index.html")

    return app
