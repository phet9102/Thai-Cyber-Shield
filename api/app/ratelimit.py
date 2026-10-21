"""
Thai Cyber Shield API - token-bucket rate limiter with abuse escalation.

Layers
------
1. Per-client token bucket   : smooth limit + small burst (anti brute-force).
2. Global token bucket       : caps total throughput (anti distributed flood).
3. Strike / ban escalation   : clients that keep hammering after being
                               throttled are banned for `ban_seconds`, and the
                               ban doubles on each repeat (max 24 h).
4. Bounded memory            : LRU map capped at `max_tracked_clients`, so an
                               attacker rotating source IPs cannot exhaust RAM.

Client identity is resolved by `client_key()`:
  * X-Forwarded-For is honoured ONLY when the TCP peer is a configured
    trusted proxy, and is walked right-to-left (the left-most value is
    attacker-controlled and must never be trusted blindly).
  * IPv6 clients are aggregated to their /64 because a single subscriber
    usually controls the whole /64 and could otherwise rotate addresses.

NOTE: state is per-process. With several workers/instances, put the same
algorithm behind Redis (e.g. a Lua script) - the interface stays identical.
"""
from __future__ import annotations

import asyncio
import ipaddress
import math
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from .config import IPNetwork, Settings


@dataclass
class _Bucket:
    tokens: float
    updated: float

    def take(self, now: float, rate: float, burst: float, cost: float) -> float:
        """Refill, then try to take `cost` tokens.

        Returns 0.0 when allowed, otherwise the seconds until enough tokens
        will be available.
        """
        elapsed = max(0.0, now - self.updated)          # monotonic, but be safe
        self.tokens = min(burst, self.tokens + elapsed * rate)
        self.updated = now
        if self.tokens >= cost:
            self.tokens -= cost
            return 0.0
        return (cost - self.tokens) / rate


@dataclass
class _ClientState:
    bucket: _Bucket
    strikes: int = 0
    strike_window_start: float = 0.0
    banned_until: float = 0.0
    ban_count: int = 0


@dataclass(frozen=True)
class Decision:
    allowed: bool
    retry_after: int = 0
    reason: str = ""


class RateLimiter:
    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._clients: "OrderedDict[str, _ClientState]" = OrderedDict()
        self._global = _Bucket(tokens=float(settings.global_burst), updated=time.monotonic())
        self._lock = asyncio.Lock()

    async def check(self, key: str, cost: float = 1.0) -> Decision:
        now = time.monotonic()
        async with self._lock:                       # O(1) critical section
            state = self._clients.get(key)
            if state is None:
                state = _ClientState(bucket=_Bucket(float(self._s.ip_burst), now))
                self._clients[key] = state
                if len(self._clients) > self._s.max_tracked_clients:
                    self._clients.popitem(last=False)          # evict LRU
            else:
                self._clients.move_to_end(key)

            # 1) active ban
            if state.banned_until > now:
                return Decision(False, _ceil(state.banned_until - now), "BANNED")

            # 2) per-client bucket
            wait = state.bucket.take(now, self._s.ip_rate_per_s, self._s.ip_burst, cost)
            if wait > 0.0:
                self._strike(state, now)
                if state.banned_until > now:
                    return Decision(False, _ceil(state.banned_until - now), "BANNED")
                return Decision(False, _ceil(wait), "CLIENT_RATE_LIMIT")

            # 3) global bucket (refund the client token if global is empty,
            #    so a global brown-out does not penalise innocent clients)
            gwait = self._global.take(
                now, self._s.global_rate_per_s, self._s.global_burst, cost
            )
            if gwait > 0.0:
                state.bucket.tokens = min(self._s.ip_burst, state.bucket.tokens + cost)
                return Decision(False, _ceil(gwait), "GLOBAL_RATE_LIMIT")

            return Decision(True)

    def _strike(self, state: _ClientState, now: float) -> None:
        if now - state.strike_window_start > self._s.ban_window_s:
            state.strike_window_start = now
            state.strikes = 0
        state.strikes += 1
        if state.strikes >= self._s.ban_strikes:
            state.ban_count += 1
            duration = min(self._s.ban_seconds * (2 ** (state.ban_count - 1)), 86_400)
            state.banned_until = now + duration
            state.strikes = 0


def _ceil(seconds: float) -> int:
    return max(1, int(math.ceil(seconds)))


# ---------------------------------------------------------------------------
# Client identity
# ---------------------------------------------------------------------------
def _parse_ip(value: str) -> Optional[ipaddress._BaseAddress]:
    value = value.strip()
    if not value or len(value) > 45:
        return None
    if value.startswith("[") and "]" in value:          # "[2001:db8::1]:443"
        value = value[1 : value.index("]")]
    elif value.count(":") == 1:                          # "1.2.3.4:5678"
        value = value.split(":", 1)[0]
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_trusted(ip: ipaddress._BaseAddress, trusted: Sequence[IPNetwork]) -> bool:
    return any(ip.version == net.version and ip in net for net in trusted)


def _key_for(ip: ipaddress._BaseAddress) -> str:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.IPv6Network((int(ip) >> 64 << 64, 64)))
    return str(ip)


def client_key(
    peer_host: Optional[str],
    xff_values: Iterable[str],
    trusted: Sequence[IPNetwork],
) -> str:
    """Return the rate-limit identity for a request."""
    peer = _parse_ip(peer_host or "")
    if peer is None:
        return "unknown-peer"           # still rate limited, as one shared bucket

    if trusted and _is_trusted(peer, trusted):
        hops: list[str] = []
        for header_value in xff_values:
            hops.extend(h for h in header_value.split(",") if h.strip())
        # Walk right-to-left, skipping our own proxies; first untrusted hop wins.
        for hop in reversed(hops[-20:]):                 # cap header abuse
            ip = _parse_ip(hop)
            if ip is None:
                break                                    # garbage -> stop, use peer
            if not _is_trusted(ip, trusted):
                return _key_for(ip)
    return _key_for(peer)
