"""
Thai Cyber Shield API - application entry point.

Run (behind a TLS-terminating reverse proxy):
    uvicorn app.main:app --host 127.0.0.1 --port 8000 \
        --no-server-header --no-proxy-headers --no-date-header \
        --limit-concurrency 256 --timeout-keep-alive 5 \
        --h11-max-incomplete-event-size 16384

`--no-proxy-headers` matters: client IP resolution is done by our own
right-to-left X-Forwarded-For walker against TCS_TRUSTED_PROXIES, never by
blindly trusting the header.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware

from .config import load_settings
from .engine import EngineRejectedInput, EngineUnavailable, SecureEngineRunner
from .models import AnalysisResponse, ErrorResponse, PhoneRequest, SmsRequest, UrlRequest
from .ratelimit import RateLimiter
from .sanitize import attack_signatures, fingerprint
from .security import (
    BodyLimitMiddleware,
    ContentTypeMiddleware,
    HostAllowListMiddleware,
    RateLimitMiddleware,
    RequestIdMiddleware,
    SecurityHeadersMiddleware,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("tcs.api")

settings = load_settings()           # fail fast on insecure configuration
limiter = RateLimiter(settings)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Binary verification happens here: the service refuses to start with a
    # missing, writable or tampered engine (fail closed).
    app.state.runner = SecureEngineRunner(settings)
    log.info("engine verified, env=%s", settings.env)
    yield


app = FastAPI(
    title="Thai Cyber Shield API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

# ---------------------------------------------------------------------------
# Middleware. Starlette wraps in reverse order of add_middleware(), so the
# LAST one added is the OUTERMOST. Read bottom-up for request flow.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),   # explicit list, never "*"
    allow_credentials=False,                        # no cookies -> no CSRF surface
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Retry-After"],
    max_age=600,
)
app.add_middleware(ContentTypeMiddleware)
app.add_middleware(BodyLimitMiddleware, settings=settings)
app.add_middleware(RateLimitMiddleware, limiter=limiter, settings=settings)
app.add_middleware(HostAllowListMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(SecurityHeadersMiddleware, settings=settings)
app.add_middleware(RequestIdMiddleware)


def _rid(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def _error(status: int, code: str, request: Request, headers: dict | None = None) -> JSONResponse:
    body = ErrorResponse(error=code, request_id=_rid(request)).model_dump()
    return JSONResponse(status_code=status, content=body, headers=headers)


# ---------------------------------------------------------------------------
# Exception handlers: never reflect input, never leak stack traces.
# FastAPI's default 422 body echoes the offending "input" back - that is a
# reflection vector and a data leak, so it is replaced here.
# ---------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {
            "field": ".".join(str(p) for p in err.get("loc", ())[1:]) or "body",
            "reason": str(err.get("type", "invalid"))[:40],
        }
        for err in exc.errors()[:5]
    ]
    return JSONResponse(
        status_code=422,
        content={"error": "INVALID_INPUT", "details": details, "request_id": _rid(request)},
    )


@app.exception_handler(StarletteHTTPException)
async def on_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 400: "BAD_REQUEST"}.get(
        exc.status_code, "HTTP_ERROR"
    )
    return _error(exc.status_code, code, request)


@app.exception_handler(Exception)
async def on_unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error rid=%s", _rid(request))
    return _error(500, "INTERNAL_ERROR", request)


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------
async def _analyze(mode: str, text: str, request: Request) -> JSONResponse:
    runner: SecureEngineRunner = request.app.state.runner
    rid = _rid(request)

    sigs = attack_signatures(text)
    if sigs:
        # Telemetry only (fingerprint, never raw content - PDPA/log injection)
        log.warning("attack_signature rid=%s mode=%s sigs=%s fp=%s",
                    rid, mode, ",".join(sigs), fingerprint(text))

    try:
        result = await runner.analyze(mode, text)
    except EngineRejectedInput as exc:
        return _error(422, exc.code, request)
    except EngineUnavailable as exc:
        log.error("engine unavailable rid=%s code=%s", rid, exc.code)
        return _error(503, "SERVICE_UNAVAILABLE", request, {"Retry-After": "5"})

    log.info("analysis rid=%s mode=%s score=%d level=%s fp=%s len=%d",
             rid, mode, result.score, result.level, fingerprint(text), len(text))

    response = AnalysisResponse(
        request_id=rid,
        mode=result.mode,
        score=result.score,
        level=result.level,
        findings=list(result.findings),
        host=result.host,
        engine=result.engine,
    )
    return JSONResponse(status_code=200, content=response.model_dump())


@app.post("/api/v1/analyze/sms", response_model=AnalysisResponse)
async def analyze_sms(body: SmsRequest, request: Request) -> JSONResponse:
    return await _analyze("sms", body.message, request)


@app.post("/api/v1/analyze/url", response_model=AnalysisResponse)
async def analyze_url(body: UrlRequest, request: Request) -> JSONResponse:
    return await _analyze("url", body.url, request)


@app.post("/api/v1/analyze/phone", response_model=AnalysisResponse)
async def analyze_phone(body: PhoneRequest, request: Request) -> JSONResponse:
    return await _analyze("phone", body.phone, request)


@app.get("/api/health")
async def health(request: Request) -> JSONResponse:
    runner: SecureEngineRunner = request.app.state.runner
    ok = runner.available
    # Deliberately minimal: no versions, paths or internals (recon surface)
    return JSONResponse(status_code=200 if ok else 503, content={"status": "ok" if ok else "degraded"})
