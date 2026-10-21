"""
Thai Cyber Shield API - input sanitation & attack-signature telemetry.

Design principles (why this file looks the way it does)
-------------------------------------------------------
* VALIDATE input, ENCODE output.  HTML-escaping here would corrupt the
  evidence the engine must analyse (e.g. "&lt;" instead of "<") and gives a
  false sense of safety. XSS is prevented where output meets HTML: the
  frontend renders with textContent only, and this API answers with
  `application/json` + `X-Content-Type-Options: nosniff`, never HTML.
* No Unicode NFKC folding: folding would erase homoglyph / fullwidth /
  zero-width evidence that the engine reports. We only remove bytes that are
  dangerous for *every* downstream consumer (NUL, C0/C1 controls).
* SQL injection: this service has no database. If one is added, use bound
  parameters only - signature lists are telemetry, not a defence.
* Command injection: impossible by construction - the engine is launched
  with an argv list (no shell) and user data travels over stdin only.
"""
from __future__ import annotations

import hashlib
import re
from typing import List

# C0 controls except TAB(09) LF(0A) CR(0D); DEL; C1 controls
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_NEWLINES_RE = re.compile(r"\r\n?| | |\u0085")

# Characters that are never legal *unencoded* in a URL (RFC 3986) and are the
# building blocks of markup / template / shell injection.
_URL_FORBIDDEN_RE = re.compile(r"[<>\"`{}\\^|]")

# Phone: ASCII digits, Thai digits, fullwidth digits/plus, common separators.
_PHONE_ALLOWED_RE = re.compile(r"^[+＋0-9๐-๙０-９ ()\-./]{3,32}$")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")

# Linear-time patterns only (no nested quantifiers) -> no ReDoS.
_SIGNATURES = {
    "XSS": re.compile(
        r"<\s*(script|iframe|svg|img|object|embed|style)\b|javascript\s*:|"
        r"\bon(error|load|click|mouseover|focus)\s*=|srcdoc\s*=",
        re.IGNORECASE,
    ),
    "SQLI": re.compile(
        r"\bunion\s+(all\s+)?select\b|'\s*or\s*'?\d|\bor\s+1\s*=\s*1\b|"
        r";\s*(drop|delete|insert|update)\s|--\s*$|/\*.*?\*/|\bsleep\s*\(",
        re.IGNORECASE,
    ),
    "CMDI": re.compile(r"[;&|]\s*(rm|curl|wget|bash|sh|nc|python)\b|\$\(|`[^`]*`"),
    "PATH_TRAVERSAL": re.compile(r"\.\./|\.\.\\|%2e%2e[/%]", re.IGNORECASE),
    "TEMPLATE": re.compile(r"\{\{.*?\}\}|\$\{.*?\}|<%.*?%>"),
    "JNDI": re.compile(r"\$\{\s*jndi\s*:", re.IGNORECASE),
    "FORMAT_STRING": re.compile(r"%(\d+\$)?[-+ #0]*\d*(hh|h|l|ll)?[nsxp]"),
}


class SanitizationError(ValueError):
    """Raised with a short, non-reflective reason (never includes the input)."""


def clean_text(value: str, *, max_chars: int, max_bytes: int, allow_newlines: bool) -> str:
    if not isinstance(value, str):
        raise SanitizationError("must be a string")

    # Lone surrogates cannot be encoded -> reject instead of silently replacing
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise SanitizationError("invalid unicode") from exc
    if len(encoded) > max_bytes:
        raise SanitizationError("too long")

    value = _NEWLINES_RE.sub("\n", value)
    if not allow_newlines:
        value = value.replace("\n", " ").replace("\t", " ")
    value = _CONTROL_RE.sub("", value)
    value = value.strip()

    if not value:
        raise SanitizationError("empty")
    if len(value) > max_chars:
        raise SanitizationError("too long")
    return value


def clean_url(value: str) -> str:
    value = clean_text(value, max_chars=2048, max_bytes=8192, allow_newlines=False)
    if _URL_FORBIDDEN_RE.search(value):
        raise SanitizationError("contains characters not allowed in a URL")
    return value


def clean_phone(value: str) -> str:
    value = clean_text(value, max_chars=32, max_bytes=128, allow_newlines=False)
    if not _PHONE_ALLOWED_RE.fullmatch(value):
        raise SanitizationError("contains characters not allowed in a phone number")
    if sum(ch.isdigit() for ch in value) < 3:
        raise SanitizationError("too few digits")
    return value


def attack_signatures(value: str) -> List[str]:
    """Telemetry only: which attack families does this payload resemble?"""
    sample = value[:4096]
    return sorted(name for name, rx in _SIGNATURES.items() if rx.search(sample))


def fingerprint(value: str) -> str:
    """Privacy-preserving log identifier (PDPA): never log raw user content."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def safe_request_id(candidate: str | None, fallback: str) -> str:
    """Accept a client X-Request-ID only if it cannot inject into logs/headers."""
    if candidate and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return fallback
