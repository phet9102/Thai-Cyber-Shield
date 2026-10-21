"""
Thai Cyber Shield API - Secure Process Interceptor for the Ada engine.

Guarantees
----------
* No shell, ever: `asyncio.create_subprocess_exec(*argv)` with a fixed argv
  list. The only variable element is the mode, checked against a frozenset.
  User data is written to stdin -> option injection ("-rf"), quoting bugs and
  `/proc/<pid>/cmdline` leaks are impossible.
* Binary integrity: absolute path, resolved symlinks, regular file, not
  group/world-writable, executable, and (in production) SHA-256 pinned.
* Hostile-child containment: minimal environment, cwd="/", own process
  group, optional `prlimit` caps (CPU seconds, address space, open files,
  no file writes, no core dumps), hard wall-clock timeout with SIGKILL of
  the whole group, bounded stdout read, stderr discarded.
* Back-pressure: bounded concurrency (semaphore with acquire timeout) and a
  circuit breaker so a failing engine degrades to fast 503s instead of
  piling up processes.
* Zero trust on output: strict JSON parsing (duplicate keys / NaN rejected),
  then Pydantic validation against a closed vocabulary.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import signal
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from pydantic import ValidationError

from .config import Settings
from .models import EngineError, EngineResult

log = logging.getLogger("tcs.engine")

ALLOWED_MODES = frozenset({"sms", "url", "phone"})
MAX_STDIN_BYTES = 8_192          # mirrors TCS_Types.Max_Raw_Bytes
MAX_STDOUT_BYTES = 16_384        # engine emits one short JSON line
_SAFE_ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}


class EngineFailure(Exception):
    """Base class. `code` is a short constant safe to return to clients."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class EngineRejectedInput(EngineFailure):
    """The engine refused the input (exit code 2) -> HTTP 422."""


class EngineUnavailable(EngineFailure):
    """Timeout, crash, overload or open circuit -> HTTP 503."""


# ---------------------------------------------------------------------------
class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown_s: float = 30.0) -> None:
        self._threshold = threshold
        self._cooldown = cooldown_s
        self._failures = 0
        self._open_until = 0.0

    def allow(self) -> bool:
        return time.monotonic() >= self._open_until

    def success(self) -> None:
        self._failures = 0

    def failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._open_until = time.monotonic() + self._cooldown
            self._failures = 0
            log.error("engine circuit opened for %.0fs", self._cooldown)


# ---------------------------------------------------------------------------
def _reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _strict_json(raw: bytes) -> Dict[str, Any]:
    text = raw.decode("utf-8", "strict")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) != 1:
        raise ValueError("engine must emit exactly one line")
    obj = json.loads(
        lines[0],
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_constant,
    )
    if not isinstance(obj, dict):
        raise ValueError("engine output is not an object")
    return obj


async def _read_limited(stream: asyncio.StreamReader, limit: int) -> bytes:
    chunks: List[bytes] = []
    total = 0
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise EngineUnavailable("ENGINE_OUTPUT_TOO_LARGE")
        chunks.append(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
class SecureEngineRunner:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._path = self._verify_binary(settings.engine_path, settings.engine_sha256)
        self._prlimit = self._verify_prlimit(settings) if settings.engine_use_prlimit else None
        self._sem = asyncio.Semaphore(settings.engine_max_concurrency)
        self._breaker = CircuitBreaker()

    # -- start-up checks (fail closed) -------------------------------------
    @staticmethod
    def _verify_binary(path: str, expected_sha256: str | None) -> str:
        p = Path(path)
        if not p.is_absolute():
            raise RuntimeError("engine path must be absolute")
        real = p.resolve(strict=True)
        st = real.stat()
        if not stat.S_ISREG(st.st_mode):
            raise RuntimeError("engine is not a regular file")
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError("engine binary is group/world writable")
        if not os.access(real, os.X_OK):
            raise RuntimeError("engine binary is not executable")
        if expected_sha256:
            digest = hashlib.sha256(real.read_bytes()).hexdigest()
            if not hmac.compare_digest(digest, expected_sha256):
                raise RuntimeError("engine binary SHA-256 mismatch (tampered?)")
        return str(real)

    @staticmethod
    def _verify_prlimit(settings: Settings) -> str:
        p = Path(settings.prlimit_path)
        if not p.is_absolute() or not p.is_file() or not os.access(p, os.X_OK):
            raise RuntimeError("prlimit not found; install util-linux or disable it")
        return str(p.resolve(strict=True))

    def _argv(self, mode: str) -> List[str]:
        if mode not in ALLOWED_MODES:                    # closed set, no echo
            raise ValueError("invalid mode")
        argv = [self._path, mode]
        if self._prlimit:
            argv = [
                self._prlimit,
                "--cpu=2",               # CPU seconds
                "--as=134217728",        # 128 MiB address space
                "--nofile=16",           # open file descriptors
                "--fsize=0",             # cannot write files
                "--core=0",              # no core dumps (memory disclosure)
                "--",
                *argv,
            ]
        return argv

    @property
    def available(self) -> bool:
        return self._breaker.allow()

    # -- main entry ---------------------------------------------------------
    async def analyze(self, mode: str, text: str) -> EngineResult:
        if not self._breaker.allow():
            raise EngineUnavailable("ENGINE_CIRCUIT_OPEN")

        payload = text.encode("utf-8", "strict")
        if len(payload) > MAX_STDIN_BYTES:
            raise EngineRejectedInput("INPUT_TOO_LONG")

        argv = self._argv(mode)

        try:
            await asyncio.wait_for(self._sem.acquire(), timeout=1.0)
        except asyncio.TimeoutError:
            raise EngineUnavailable("ENGINE_BUSY") from None

        try:
            return await self._run(argv, mode, payload)
        finally:
            self._sem.release()

    async def _run(self, argv: List[str], mode: str, payload: bytes) -> EngineResult:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=_SAFE_ENV,
            cwd="/",
            close_fds=True,
            start_new_session=True,      # own process group -> killpg on timeout
        )

        async def _exchange() -> Tuple[bytes, int]:
            assert proc.stdin is not None and proc.stdout is not None
            try:
                proc.stdin.write(payload)
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass                      # engine exited early (e.g. rejected)
            finally:
                proc.stdin.close()
            out = await _read_limited(proc.stdout, MAX_STDOUT_BYTES)
            rc = await proc.wait()
            return out, rc

        try:
            stdout, rc = await asyncio.wait_for(_exchange(), timeout=self._s.engine_timeout_s)
        except asyncio.TimeoutError:
            self._kill(proc)
            self._breaker.failure()
            raise EngineUnavailable("ENGINE_TIMEOUT") from None
        except EngineUnavailable:
            self._kill(proc)
            self._breaker.failure()
            raise
        finally:
            if proc.returncode is None:
                self._kill(proc)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    log.error("engine process did not exit after SIGKILL")

        try:
            obj = _strict_json(stdout)
        except (ValueError, UnicodeDecodeError):
            self._breaker.failure()
            log.error("engine produced malformed output (rc=%s)", rc)
            raise EngineUnavailable("ENGINE_BAD_OUTPUT") from None

        if rc == 0:
            try:
                result = EngineResult.model_validate(obj)
            except ValidationError:
                self._breaker.failure()
                log.error("engine output failed schema validation")
                raise EngineUnavailable("ENGINE_BAD_OUTPUT") from None
            if result.mode != mode:
                self._breaker.failure()
                raise EngineUnavailable("ENGINE_MODE_MISMATCH")
            self._breaker.success()
            return result

        if rc == 2:
            try:
                err = EngineError.model_validate(obj)
            except ValidationError:
                raise EngineUnavailable("ENGINE_BAD_OUTPUT") from None
            self._breaker.success()          # a clean rejection is healthy
            raise EngineRejectedInput(err.error)

        self._breaker.failure()
        log.error("engine failed with exit code %s", rc)
        raise EngineUnavailable("ENGINE_FAULT")

    @staticmethod
    def _kill(proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
