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

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from typing import AsyncIterator, List, Optional

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.cors import CORSMiddleware

from .config import load_settings
from .engine import EngineRejectedInput, EngineUnavailable, SecureEngineRunner
from .extract import Identifier, extract_identifiers, identifier_from_field
from .fusion import fuse
from .models import (
    AnalysisResponse,
    EmailRequest,
    EngineResult,
    ErrorResponse,
    IdentifierOut,
    PhoneRequest,
    ReportRequest,
    ReportResponse,
    SlipOut,
    SmsRequest,
    SocialRequest,
    TradeRequest,
    UrlRequest,
)
from .ratelimit import RateLimiter
from .sanitize import attack_signatures, fingerprint
from .slipparse import build_fact_sheet, extract_slip, parse_slip_qr
from .store import ReportStore, Reputation, StoreError
from .vision import ImageRejected, OcrRunner, OcrUnavailable, analyse_image, numeric_inconsistency
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
    app.state.ocr = OcrRunner(settings)
    # The report store is optional: if the database is unreachable the
    # analysers keep working and reputation lookups are skipped.
    try:
        store = ReportStore(settings)
        await asyncio.to_thread(store.init_schema)
        app.state.store = store
    except Exception:
        log.exception("report store unavailable - continuing without reputation data")
        app.state.store = None
    log.info("engine verified, env=%s", settings.env)
    yield


app = FastAPI(
    title="Thai Cyber Shield API",
    version="2.0.0",
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
    allow_headers=["Content-Type", "X-Request-ID", "X-TCS-Client"],
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
_EXPECTED_RE = re.compile(r"^[0-9]{1,11}(\.[0-9]{1,2})?$")


def _client_key(request: Request) -> str:
    return str(request.scope.get("state", {}).get("client_key", "unknown"))


async def _reputations(request: Request, idents: List[Identifier]) -> List[tuple]:
    store: Optional[ReportStore] = request.app.state.store
    if store is None or not idents:
        return [(i, Reputation(0, 0, 0)) for i in idents]
    try:
        reps = await asyncio.to_thread(store.reputation, idents)
    except Exception:
        log.exception("reputation lookup failed rid=%s", _rid(request))
        reps = {}
    return [(i, reps.get(i.kind + "|" + i.key, Reputation(0, 0, 0))) for i in idents]


async def _engine(request: Request, mode: str, text: str) -> EngineResult:
    runner: SecureEngineRunner = request.app.state.runner
    sigs = attack_signatures(text)
    if sigs:
        # Telemetry only (fingerprint, never raw content - PDPA/log injection)
        log.warning("attack_signature rid=%s mode=%s sigs=%s fp=%s",
                    _rid(request), mode, ",".join(sigs), fingerprint(text))
    return await runner.analyze(mode, text)


async def _respond(request: Request, result: EngineResult, idents: List[Identifier],
                   *, slip: Optional[SlipOut] = None, ocr_text: Optional[str] = None,
                   ocr_conf: Optional[int] = None) -> JSONResponse:
    pairs = await _reputations(request, idents)
    score, level, findings = fuse(result.score, list(result.findings), pairs)
    log.info("analysis rid=%s mode=%s score=%d level=%s ids=%d",
             _rid(request), result.mode, score, level, len(idents))
    response = AnalysisResponse(
        request_id=_rid(request),
        mode=result.mode,
        score=score,
        level=level,
        findings=findings,
        host=result.host,
        engine=result.engine,
        identifiers=[
            IdentifierOut(kind=i.kind, display=i.display, reporters=r.reporters,
                          reports=r.reports, linked_reports=r.linked_reports)
            for i, r in pairs
        ],
        slip=slip,
        ocr_text=ocr_text,
        ocr_conf=ocr_conf,
    )
    return JSONResponse(status_code=200, content=response.model_dump())


async def _analyze(request: Request, mode: str, text: str,
                   idents: List[Identifier]) -> JSONResponse:
    try:
        result = await _engine(request, mode, text)
    except EngineRejectedInput as exc:
        return _error(422, exc.code, request)
    except EngineUnavailable as exc:
        log.error("engine unavailable rid=%s code=%s", _rid(request), exc.code)
        return _error(503, "SERVICE_UNAVAILABLE", request, {"Retry-After": "5"})
    return await _respond(request, result, idents)


def _one(kind: str, value: str) -> List[Identifier]:
    ident = identifier_from_field(kind, value)
    return [ident] if ident else []


# --- text analysers ---------------------------------------------------------
@app.post("/api/v1/analyze/sms", response_model=AnalysisResponse)
async def analyze_sms(body: SmsRequest, request: Request) -> JSONResponse:
    return await _analyze(request, "sms", body.message, extract_identifiers(body.message))


@app.post("/api/v1/analyze/url", response_model=AnalysisResponse)
async def analyze_url(body: UrlRequest, request: Request) -> JSONResponse:
    return await _analyze(request, "url", body.url, _one("facebook", body.url) or _one("url", body.url))


@app.post("/api/v1/analyze/phone", response_model=AnalysisResponse)
async def analyze_phone(body: PhoneRequest, request: Request) -> JSONResponse:
    return await _analyze(request, "phone", body.phone, _one("phone", body.phone))


@app.post("/api/v1/analyze/trade", response_model=AnalysisResponse)
async def analyze_trade(body: TradeRequest, request: Request) -> JSONResponse:
    return await _analyze(request, "trade", body.chat, extract_identifiers(body.chat))


@app.post("/api/v1/analyze/social", response_model=AnalysisResponse)
async def analyze_social(body: SocialRequest, request: Request) -> JSONResponse:
    return await _analyze(request, "social", body.url, _one("facebook", body.url) or _one("url", body.url))


@app.post("/api/v1/analyze/email", response_model=AnalysisResponse)
async def analyze_email(body: EmailRequest, request: Request) -> JSONResponse:
    return await _analyze(request, "email", body.email, _one("email", body.email))


# --- image analysers ----------------------------------------------------------
async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read(settings.max_upload_bytes + 1)
    await file.close()
    if len(data) > settings.max_upload_bytes:
        raise ImageRejected("IMAGE_TOO_LARGE")
    return data


def _vision_error(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, ImageRejected):
        return _error(422, str(exc), request)
    log.error("ocr unavailable rid=%s code=%s", _rid(request), exc)
    return _error(503, "SERVICE_UNAVAILABLE", request, {"Retry-After": "10"})


@app.post("/api/v1/analyze/chat-image", response_model=AnalysisResponse)
async def analyze_chat_image(request: Request, file: UploadFile = File(...)) -> JSONResponse:
    try:
        data = await _read_upload(file)
        vis = await analyse_image(data, settings, request.app.state.ocr)
    except (ImageRejected, OcrUnavailable) as exc:
        return _vision_error(request, exc)

    text = vis.text.strip()
    if len(text) < 3:
        return _error(422, "NO_TEXT_FOUND", request)
    chat = text[:4000]
    try:
        result = await _engine(request, "trade", chat)
    except EngineRejectedInput as exc:
        return _error(422, exc.code, request)
    except EngineUnavailable:
        return _error(503, "SERVICE_UNAVAILABLE", request, {"Retry-After": "5"})
    return await _respond(request, result, extract_identifiers(chat),
                          ocr_text=chat[:3000], ocr_conf=vis.mean_conf)


@app.post("/api/v1/analyze/slip", response_model=AnalysisResponse)
async def analyze_slip(request: Request, file: UploadFile = File(...),
                       expected_amount: Optional[str] = Form(default=None, max_length=20)) -> JSONResponse:
    expected = None
    if expected_amount and expected_amount.strip():
        expected = expected_amount.strip().replace(",", "")
        if not _EXPECTED_RE.fullmatch(expected):
            return _error(422, "INVALID_EXPECTED_AMOUNT", request)
    try:
        data = await _read_upload(file)
        vis = await analyse_image(data, settings, request.app.state.ocr)
    except (ImageRejected, OcrUnavailable) as exc:
        return _vision_error(request, exc)

    facts = extract_slip(vis.text, vis.qr_payloads)

    duplicate = False
    store: Optional[ReportStore] = request.app.state.store
    if store is not None and facts.ref:
        try:
            duplicate = await asyncio.to_thread(store.slip_seen_elsewhere, facts.ref,
                                                _client_key(request))
        except Exception:
            log.exception("slip duplicate check failed rid=%s", _rid(request))

    sheet = build_fact_sheet(
        facts, expected=expected, edited=bool(vis.edited_by),
        inconsistent=numeric_inconsistency(vis.words, facts.amount_raw),
        duplicate=duplicate, ocr_conf=vis.mean_conf)
    try:
        result = await _engine(request, "slip", sheet)
    except EngineRejectedInput as exc:
        return _error(422, exc.code, request)
    except EngineUnavailable:
        return _error(503, "SERVICE_UNAVAILABLE", request, {"Retry-After": "5"})

    qr_info = parse_slip_qr(facts.qr) if facts.qr else None
    slip = SlipOut(
        bank=facts.bank,
        amount=facts.amount,
        time=facts.when.strftime("%d/%m/%Y %H:%M") if facts.when else None,
        ref_tail=facts.ref[-4:] if facts.ref else None,
        qr_found=bool(facts.qr),
        qr_valid=(bool(qr_info and qr_info["crc_ok"]) if facts.qr else None),
    )
    return await _respond(request, result, extract_identifiers(vis.text), slip=slip,
                          ocr_text=vis.text[:3000], ocr_conf=vis.mean_conf)


# --- community reports ----------------------------------------------------------
@app.post("/api/v1/reports", response_model=ReportResponse)
async def submit_report(body: ReportRequest, request: Request) -> JSONResponse:
    store: Optional[ReportStore] = request.app.state.store
    if store is None:
        return _error(503, "SERVICE_UNAVAILABLE", request, {"Retry-After": "30"})

    idents: List[Identifier] = []
    for kind in ("phone", "bank_account", "facebook", "email", "url"):
        value = getattr(body, kind)
        if value:
            ident = identifier_from_field(kind, value)
            if ident is None and kind == "url":
                continue
            if ident is None:
                return _error(422, f"INVALID_{kind.upper()}", request)
            idents.append(ident)
    if not idents:
        return _error(422, "NO_IDENTIFIER", request)

    try:
        await asyncio.to_thread(store.add_report, _client_key(request), body.category, idents)
    except StoreError as exc:
        status = {"REPORT_LIMIT_REACHED": 429, "ALREADY_REPORTED": 409}.get(str(exc), 422)
        return _error(status, str(exc), request)
    except Exception:
        log.exception("report store write failed rid=%s", _rid(request))
        return _error(503, "SERVICE_UNAVAILABLE", request, {"Retry-After": "30"})

    log.info("report accepted rid=%s category=%s ids=%d", _rid(request), body.category, len(idents))
    return JSONResponse(status_code=201, content=ReportResponse(
        request_id=_rid(request), accepted=True, identifiers=len(idents)).model_dump())


@app.get("/api/health")
async def health(request: Request) -> JSONResponse:
    runner: SecureEngineRunner = request.app.state.runner
    ok = runner.available
    # Deliberately minimal: no versions, paths or internals (recon surface)
    return JSONResponse(status_code=200 if ok else 503, content={"status": "ok" if ok else "degraded"})
