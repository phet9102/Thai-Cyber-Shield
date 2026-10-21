"""
Thai Cyber Shield API - pure-ASGI security middleware.

Pure ASGI (not BaseHTTPMiddleware) so each layer runs before any routing or
body parsing, adds negligible overhead, and cannot be bypassed by streaming.

Order (outermost -> innermost) as wired in main.py:
    RequestId -> SecurityHeaders -> HostAllowList -> RateLimit -> BodyLimit
    -> ContentType -> CORS -> FastAPI router
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Awaitable, Callable, Iterable, List, MutableMapping, Tuple, Any

from .config import Settings
from .ratelimit import RateLimiter, client_key
from .sanitize import safe_request_id

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

log = logging.getLogger("tcs.security")


def _header(scope: Scope, name: bytes) -> List[str]:
    return [
        v.decode("latin-1")
        for k, v in scope.get("headers", [])
        if k.lower() == name
    ]


async def send_json_error(
    send: Send,
    status: int,
    error: str,
    request_id: str,
    extra_headers: Iterable[Tuple[bytes, bytes]] = (),
) -> None:
    body = json.dumps({"error": error, "request_id": request_id}).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _rid(scope: Scope) -> str:
    return scope.get("state", {}).get("request_id", "-")


# ---------------------------------------------------------------------------
class RequestIdMiddleware:
    """Correlation id for logs; a client-supplied id is only accepted if it
    matches ^[A-Za-z0-9-]{8,64}$ (no header/log injection)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        supplied = (_header(scope, b"x-request-id") or [None])[0]
        rid = safe_request_id(supplied, uuid.uuid4().hex)
        scope.setdefault("state", {})["request_id"] = rid

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", rid.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware:
    """Enterprise security headers on EVERY response, including 4xx/5xx
    produced by inner middleware. Removes the Server banner."""

    API_CSP = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'none'; sandbox"
    )

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings
        base: List[Tuple[bytes, bytes]] = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"permissions-policy",
             b"accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
             b"magnetometer=(), microphone=(), payment=(), usb=(), "
             b"interest-cohort=()"),
            (b"cross-origin-opener-policy", b"same-origin"),
            (b"cross-origin-resource-policy", b"same-site"),
            (b"cross-origin-embedder-policy", b"require-corp"),
            (b"x-permitted-cross-domain-policies", b"none"),
            (b"cache-control", b"no-store, max-age=0"),
            (b"pragma", b"no-cache"),
        ]
        if settings.is_production:
            base.append(
                (b"strict-transport-security",
                 b"max-age=63072000; includeSubDomains; preload")
            )
        self._base = base

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path: str = scope.get("path", "")
        docs = (not self.settings.is_production) and (
            path.startswith("/docs") or path.startswith("/openapi")
        )

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                drop = {b"server", b"x-powered-by"}
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in drop]
                headers.extend(self._base)
                if not docs:          # Swagger UI (dev only) needs scripts
                    headers.append((b"content-security-policy", self.API_CSP.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


# ---------------------------------------------------------------------------
class RateLimitMiddleware:
    """Token bucket per client + global bucket, evaluated BEFORE the body is
    read so floods are rejected at minimal cost."""

    def __init__(self, app: ASGIApp, limiter: RateLimiter, settings: Settings) -> None:
        self.app = app
        self.limiter = limiter
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        peer = (scope.get("client") or (None, None))[0]
        key = client_key(peer, _header(scope, b"x-forwarded-for"), self.settings.trusted_proxies)

        method = scope.get("method", "GET")
        path = scope.get("path", "")
        cost = 0.2 if method in ("OPTIONS", "HEAD") or path == "/api/health" else 1.0

        decision = await self.limiter.check(key, cost)
        if not decision.allowed:
            log.warning("rate_limited reason=%s rid=%s", decision.reason, _rid(scope))
            await send_json_error(
                send, 429, "RATE_LIMITED", _rid(scope),
                [(b"retry-after", str(decision.retry_after).encode())],
            )
            return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
class BodyLimitMiddleware:
    """Rejects oversized bodies (Content-Length AND actual streamed bytes) and
    slow-loris bodies (per-chunk read timeout). The body is buffered once
    (it is tiny by contract) and replayed to the application."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.max_bytes = settings.max_body_bytes
        self.timeout = settings.body_read_timeout_s

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") in ("GET", "HEAD", "OPTIONS"):
            return await self.app(scope, receive, send)

        cl = _header(scope, b"content-length")
        if cl:
            if len(cl) > 1 or not cl[0].isdigit() or int(cl[0]) > self.max_bytes:
                await send_json_error(send, 413, "PAYLOAD_TOO_LARGE", _rid(scope))
                return

        body = bytearray()
        more = True
        while more:
            try:
                message = await asyncio.wait_for(receive(), timeout=self.timeout)
            except asyncio.TimeoutError:
                await send_json_error(send, 408, "REQUEST_TIMEOUT", _rid(scope))
                return
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await send_json_error(send, 413, "PAYLOAD_TOO_LARGE", _rid(scope))
                return
            more = message.get("more_body", False)

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


# ---------------------------------------------------------------------------
class ContentTypeMiddleware:
    """State-changing requests must be JSON. Blocks form-encoded CSRF and
    'simple request' tricks that bypass CORS preflight."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("method") in ("POST", "PUT", "PATCH", "DELETE"):
            ctype = (_header(scope, b"content-type") or [""])[0].lower()
            media = ctype.split(";", 1)[0].strip()
            params = ctype.split(";", 1)[1].strip() if ";" in ctype else ""
            if media != "application/json" or (params and params.replace(" ", "") != "charset=utf-8"):
                await send_json_error(send, 415, "UNSUPPORTED_MEDIA_TYPE", _rid(scope))
                return
        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
class HostAllowListMiddleware:
    """Host-header allow-list (blocks DNS-rebinding / cache-poisoning /
    password-reset-link style Host attacks). The platform health probe on
    /api/health is exempt because load balancers call it with an internal
    Host header; that endpoint returns only {"status": ...}."""

    EXEMPT_PATHS = frozenset({"/api/health"})

    def __init__(self, app: ASGIApp, allowed_hosts: Iterable[str]) -> None:
        self.app = app
        self.allowed = frozenset(h.lower() for h in allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in self.EXEMPT_PATHS:
            return await self.app(scope, receive, send)
        raw = (_header(scope, b"host") or [""])[0].strip().lower()
        if raw.startswith("["):                       # [ipv6]:port
            host = raw[1:raw.find("]")] if "]" in raw else ""
        else:
            host = raw.rsplit(":", 1)[0] if raw.count(":") == 1 else raw
        if host not in self.allowed:
            await send_json_error(send, 400, "INVALID_HOST", _rid(scope))
            return
        await self.app(scope, receive, send)
