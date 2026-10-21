"""
Thai Cyber Shield API - configuration.

All settings come from environment variables and are validated ONCE at
start-up (fail fast, fail closed). A misconfiguration such as a wildcard CORS
origin in production stops the process instead of silently running insecure.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Tuple, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class ConfigError(RuntimeError):
    """Raised when the environment would produce an insecure configuration."""


def _env_list(name: str, default: str = "") -> Tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be within [{lo}, {hi}]")
    return value


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be within [{lo}, {hi}]")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    env: str
    # --- engine -----------------------------------------------------------
    engine_path: str
    engine_sha256: str | None
    engine_timeout_s: float
    engine_max_concurrency: int
    engine_use_prlimit: bool
    prlimit_path: str
    # --- HTTP surface -----------------------------------------------------
    allowed_origins: Tuple[str, ...]
    allowed_hosts: Tuple[str, ...]
    trusted_proxies: Tuple[IPNetwork, ...]
    max_body_bytes: int
    body_read_timeout_s: float
    # --- rate limiting ----------------------------------------------------
    ip_rate_per_s: float
    ip_burst: int
    global_rate_per_s: float
    global_burst: int
    ban_strikes: int
    ban_window_s: int
    ban_seconds: int
    max_tracked_clients: int
    # --- vision / OCR -----------------------------------------------------
    max_upload_bytes: int
    max_image_pixels: int
    tesseract_path: str
    ocr_langs: str
    ocr_timeout_s: float
    ocr_max_concurrency: int
    # --- report store / OSINT correlation ----------------------------------
    hash_pepper: bytes
    database_url: str
    report_daily_limit: int
    report_retention_days: int

    @property
    def is_production(self) -> bool:
        return self.env == "production"


def _ocr_langs() -> str:
    langs = os.getenv("TCS_OCR_LANGS", "tha+eng").strip()
    if not langs or any(c not in "abcdefghijklmnopqrstuvwxyz_+" for c in langs) or len(langs) > 40:
        raise ConfigError("TCS_OCR_LANGS must look like 'tha+eng'")
    return langs


def load_settings() -> Settings:
    env = os.getenv("TCS_ENV", "production").strip().lower()
    if env not in {"production", "development", "test"}:
        raise ConfigError("TCS_ENV must be production, development or test")

    origins = _env_list("TCS_ALLOWED_ORIGINS", "https://thai-cyber-shield.vercel.app")
    for origin in origins:
        if origin == "*" or "*" in origin:
            raise ConfigError("Wildcard CORS origins are forbidden")
        if env == "production" and not origin.startswith("https://"):
            raise ConfigError(f"Production origin must be https: {origin}")
        if origin.endswith("/"):
            raise ConfigError(f"Origin must not end with '/': {origin}")

    hosts = _env_list("TCS_ALLOWED_HOSTS", "api.thai-cyber-shield.example,localhost,127.0.0.1")
    if env == "production" and any(h == "*" for h in hosts):
        raise ConfigError("Wildcard Host allow-list is forbidden in production")

    proxies: list[IPNetwork] = []
    for item in _env_list("TCS_TRUSTED_PROXIES", ""):
        try:
            proxies.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ConfigError(f"Invalid TCS_TRUSTED_PROXIES entry: {item}") from exc

    sha = os.getenv("TCS_ENGINE_SHA256")
    if sha is not None:
        sha = sha.strip().lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise ConfigError("TCS_ENGINE_SHA256 must be 64 hex characters")
    elif env == "production":
        raise ConfigError("TCS_ENGINE_SHA256 is mandatory in production (binary pinning)")

    pepper = os.getenv("TCS_HASH_PEPPER", "")
    if len(pepper) < 32:
        if env == "production":
            raise ConfigError(
                "TCS_HASH_PEPPER must be set to a random secret of >= 32 characters"
            )
        pepper = "development-only-pepper-do-not-use-in-production"

    database_url = os.getenv("TCS_DATABASE_URL", "").strip()
    if database_url and not (
        database_url.startswith("postgresql://") or database_url.startswith("postgres://")
        or database_url.startswith("sqlite:///")
    ):
        raise ConfigError("TCS_DATABASE_URL must be postgresql://... or sqlite:///...")
    if database_url.startswith("postgres") and env == "production" \
            and "sslmode=require" not in database_url and "sslmode=verify" not in database_url:
        raise ConfigError("Production Postgres URL must use sslmode=require (or verify-full)")

    return Settings(
        env=env,
        engine_path=os.getenv("TCS_ENGINE_PATH", "/opt/tcs/bin/tcs_engine"),
        engine_sha256=sha,
        engine_timeout_s=_env_float("TCS_ENGINE_TIMEOUT_S", 2.0, 0.1, 10.0),
        engine_max_concurrency=_env_int("TCS_ENGINE_MAX_CONCURRENCY", 8, 1, 128),
        engine_use_prlimit=_env_bool("TCS_ENGINE_USE_PRLIMIT", True),
        prlimit_path=os.getenv("TCS_PRLIMIT_PATH", "/usr/bin/prlimit"),
        allowed_origins=origins,
        allowed_hosts=hosts,
        trusted_proxies=tuple(proxies),
        max_body_bytes=_env_int("TCS_MAX_BODY_BYTES", 65_536, 1_024, 1_048_576),
        body_read_timeout_s=_env_float("TCS_BODY_READ_TIMEOUT_S", 10.0, 1.0, 60.0),
        ip_rate_per_s=_env_float("TCS_IP_RATE_PER_S", 0.5, 0.01, 100.0),   # 30 req/min
        ip_burst=_env_int("TCS_IP_BURST", 10, 1, 1_000),
        global_rate_per_s=_env_float("TCS_GLOBAL_RATE_PER_S", 100.0, 1.0, 100_000.0),
        global_burst=_env_int("TCS_GLOBAL_BURST", 300, 1, 1_000_000),
        ban_strikes=_env_int("TCS_BAN_STRIKES", 20, 1, 10_000),
        ban_window_s=_env_int("TCS_BAN_WINDOW_S", 60, 1, 3_600),
        ban_seconds=_env_int("TCS_BAN_SECONDS", 900, 1, 86_400),
        max_tracked_clients=_env_int("TCS_MAX_TRACKED_CLIENTS", 100_000, 1_000, 10_000_000),
        max_upload_bytes=_env_int("TCS_MAX_UPLOAD_BYTES", 5 * 1024 * 1024, 64 * 1024, 20 * 1024 * 1024),
        max_image_pixels=_env_int("TCS_MAX_IMAGE_PIXELS", 24_000_000, 1_000_000, 80_000_000),
        tesseract_path=os.getenv("TCS_TESSERACT_PATH", "/usr/bin/tesseract"),
        ocr_langs=_ocr_langs(),
        ocr_timeout_s=_env_float("TCS_OCR_TIMEOUT_S", 25.0, 2.0, 120.0),
        ocr_max_concurrency=_env_int("TCS_OCR_MAX_CONCURRENCY", 1, 1, 16),
        hash_pepper=pepper.encode("utf-8"),
        database_url=database_url or "sqlite:////tmp/tcs_reports.db",
        report_daily_limit=_env_int("TCS_REPORT_DAILY_LIMIT", 5, 1, 1_000),
        report_retention_days=_env_int("TCS_REPORT_RETENTION_DAYS", 730, 30, 3_650),
    )
