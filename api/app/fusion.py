"""
Thai Cyber Shield API - risk fusion.

Combines the deterministic Ada engine verdict with community-report
reputation from the privacy-preserving store. Reputation can only RAISE
risk, and its weight depends on the number of DISTINCT reporters so a
single malicious report cannot brand someone a scammer.
"""
from __future__ import annotations

from typing import Iterable, List, Tuple

from .extract import Identifier
from .store import Reputation

LEVELS = ((80, "CRITICAL"), (60, "HIGH"), (35, "MEDIUM"), (15, "LOW"), (0, "SAFE"))


def level_of(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "SAFE"


def fuse(score: int, findings: List[str],
         reps: Iterable[Tuple[Identifier, Reputation]]) -> Tuple[int, str, List[str]]:
    best_reporters = 0
    any_linked = False
    for _, rep in reps:
        best_reporters = max(best_reporters, rep.reporters)
        any_linked = any_linked or rep.linked_reports > 0

    extra: List[Tuple[str, int]] = []
    if best_reporters >= 3:
        extra.append(("REPORTED_MANY", 60))
    elif best_reporters == 2:
        extra.append(("REPORTED_MULTIPLE", 35))
    elif best_reporters == 1:
        extra.append(("REPORTED_ONCE", 10))
    if any_linked:
        extra.append(("LINKED_TO_REPORTED", 20))

    out = list(findings)
    for code, weight in extra:
        if code not in out:
            out.append(code)
            score += weight
    score = max(0, min(100, score))
    return score, level_of(score), out[:40]
