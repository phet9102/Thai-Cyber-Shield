"""
Thai Cyber Shield API - Pydantic v2 contracts.

* Request models: strict types (no int->str coercion), extra fields
  forbidden (mass-assignment / parameter pollution), length limits enforced
  BEFORE the custom sanitizers run.
* EngineResult: the engine's stdout is treated as untrusted too (zero trust
  between our own components). Every field is re-validated against a closed
  vocabulary before it can reach a client.
"""
from __future__ import annotations

import re
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .sanitize import SanitizationError, clean_phone, clean_text, clean_url

Mode = Literal["sms", "url", "phone", "trade", "slip", "social", "email"]
Level = Literal["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

FINDING_PATTERN = r"^[A-Z0-9_]{1,40}$"
HOST_PATTERN = r"^[a-z0-9.:\-]{1,253}$"
ERROR_CODE_PATTERN = r"^[A-Z_]{1,40}$"
_FINDING_RX = re.compile(FINDING_PATTERN)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------
class SmsRequest(_StrictModel):
    message: str = Field(min_length=1, max_length=1000)

    @field_validator("message")
    @classmethod
    def _sanitize(cls, v: str) -> str:
        try:
            return clean_text(v, max_chars=1000, max_bytes=4000, allow_newlines=True)
        except SanitizationError as exc:
            raise ValueError(str(exc)) from None


class UrlRequest(_StrictModel):
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def _sanitize(cls, v: str) -> str:
        try:
            return clean_url(v)
        except SanitizationError as exc:
            raise ValueError(str(exc)) from None


class PhoneRequest(_StrictModel):
    phone: str = Field(min_length=3, max_length=32)

    @field_validator("phone")
    @classmethod
    def _sanitize(cls, v: str) -> str:
        try:
            return clean_phone(v)
        except SanitizationError as exc:
            raise ValueError(str(exc)) from None


class TradeRequest(_StrictModel):
    chat: str = Field(min_length=1, max_length=4000)

    @field_validator("chat")
    @classmethod
    def _sanitize(cls, v: str) -> str:
        try:
            return clean_text(v, max_chars=4000, max_bytes=16000, allow_newlines=True)
        except SanitizationError as exc:
            raise ValueError(str(exc)) from None


class SocialRequest(UrlRequest):
    """A Facebook (or any) link; same sanitation as UrlRequest."""


class EmailRequest(_StrictModel):
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def _sanitize(cls, v: str) -> str:
        try:
            v = clean_text(v, max_chars=254, max_bytes=1024, allow_newlines=False)
        except SanitizationError as exc:
            raise ValueError(str(exc)) from None
        if " " in v or "<" in v or ">" in v or '"' in v:
            raise ValueError("invalid e-mail")
        return v


ReportCategory = Literal[
    "item_trade", "online_shopping", "call_center", "investment", "loan",
    "romance", "job", "phishing", "fake_slip", "other",
]


class ReportRequest(_StrictModel):
    category: ReportCategory
    phone: Optional[str] = Field(default=None, max_length=32)
    bank_account: Optional[str] = Field(default=None, max_length=32)
    facebook: Optional[str] = Field(default=None, max_length=512)
    email: Optional[str] = Field(default=None, max_length=254)
    url: Optional[str] = Field(default=None, max_length=2048)
    consent: Literal[True]

    @field_validator("phone", "bank_account", "facebook", "email", "url")
    @classmethod
    def _sanitize(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not v.strip():
            return None
        try:
            return clean_text(v, max_chars=2048, max_bytes=8192, allow_newlines=False)
        except SanitizationError as exc:
            raise ValueError(str(exc)) from None


# ---------------------------------------------------------------------------
# Engine output (untrusted until validated)
# ---------------------------------------------------------------------------
class EngineResult(_StrictModel):
    ok: Literal[True]
    engine: str = Field(pattern=r"^tcs-ada/\d+\.\d+$")
    mode: Mode
    score: int = Field(ge=0, le=100)
    level: Level
    findings: List[str] = Field(max_length=32)
    host: Optional[str] = Field(default=None, pattern=HOST_PATTERN)

    @field_validator("findings")
    @classmethod
    def _codes(cls, v: List[str]) -> List[str]:
        if any(not _FINDING_RX.fullmatch(code) for code in v):
            raise ValueError("unexpected finding code")
        if len(set(v)) != len(v):
            raise ValueError("duplicate finding code")
        return v


class EngineError(_StrictModel):
    ok: Literal[False]
    engine: str = Field(pattern=r"^tcs-ada/\d+\.\d+$")
    error: str = Field(pattern=ERROR_CODE_PATTERN)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------
class IdentifierOut(_StrictModel):
    kind: Literal["phone", "bank_account", "email", "facebook", "url"]
    display: str
    reporters: int = Field(ge=0)
    reports: int = Field(ge=0)
    linked_reports: int = Field(ge=0)


class SlipOut(_StrictModel):
    bank: str
    amount: Optional[str] = None
    time: Optional[str] = None
    ref_tail: Optional[str] = None
    qr_found: bool
    qr_valid: Optional[bool] = None


class AnalysisResponse(_StrictModel):
    request_id: str
    mode: Mode
    score: int = Field(ge=0, le=100)
    level: Level
    findings: List[str]
    host: Optional[str] = None
    engine: str
    identifiers: List[IdentifierOut] = Field(default_factory=list)
    slip: Optional[SlipOut] = None
    ocr_text: Optional[str] = None
    ocr_conf: Optional[int] = None


class ReportResponse(_StrictModel):
    request_id: str
    accepted: bool
    identifiers: int


class ErrorResponse(_StrictModel):
    error: str
    request_id: str
