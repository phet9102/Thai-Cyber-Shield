"""
Thai Cyber Shield API - privacy-preserving scam-report store & OSINT
correlation.

What is stored
--------------
* Never the identifier itself. Each canonical identifier ("+66812345678",
  "fb:user:somename", a bank account...) is turned into
      HMAC-SHA256(pepper, kind + ":" + canonical)
  The pepper lives only in the server environment, so a stolen database
  cannot be reversed or brute-forced into phone numbers / accounts
  (a plain SHA-256 of a 10-digit phone number is trivially brute-forced).
* Reporter identity is also an HMAC of the rate-limit client key: used only
  to count DISTINCT reporters and enforce a daily limit, never displayed.
* No free text, no names, no screenshots.

Correlation ("digital footprint" in the scam-report sense)
----------------------------------------------------------
A single report may list several identifiers of the same scammer
(phone + bank account + Facebook + e-mail). Those identifiers become
linked through the report. When a user checks an identifier we return:
  * direct:  distinct reporters / total reports for that identifier
  * linked:  reports reachable in ONE hop - other reports that share any
             identifier that co-occurred with the checked one.
Only COUNTS are returned; linked identifiers are never revealed, so the
store cannot be used to build a profile of a person.

Anti-poisoning
--------------
* daily report limit per reporter, one counted report per reporter per
  identifier, risk weight grows with DISTINCT reporters only,
  one report = "unverified" low weight.
* retention: reports older than TCS_REPORT_RETENTION_DAYS are purged.

Backends: SQLite (development / single instance) and PostgreSQL (e.g. a free
Neon database) - same SQL, only the placeholder style differs.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

from .config import Settings
from .extract import Identifier

log = logging.getLogger("tcs.store")

REPORT_CATEGORIES = frozenset({
    "item_trade", "online_shopping", "call_center", "investment",
    "loan", "romance", "job", "phishing", "fake_slip", "other",
})

_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS reports (
           report_id     TEXT PRIMARY KEY,
           created_at    BIGINT NOT NULL,
           category      TEXT NOT NULL,
           reporter_hash TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS report_links (
           report_id TEXT NOT NULL,
           id_hash   TEXT NOT NULL,
           kind      TEXT NOT NULL,
           PRIMARY KEY (report_id, id_hash))""",
    "CREATE INDEX IF NOT EXISTS ix_links_hash ON report_links (id_hash)",
    "CREATE INDEX IF NOT EXISTS ix_reports_reporter ON reports (reporter_hash, created_at)",
    """CREATE TABLE IF NOT EXISTS slip_refs (
           ref_hash       TEXT NOT NULL,
           submitter_hash TEXT NOT NULL,
           first_seen     BIGINT NOT NULL,
           PRIMARY KEY (ref_hash, submitter_hash))""",
]


@dataclass(frozen=True)
class Reputation:
    reporters: int
    reports: int
    linked_reports: int


class StoreError(RuntimeError):
    pass


class ReportStore:
    def __init__(self, settings: Settings) -> None:
        self._pepper = settings.hash_pepper
        self._daily_limit = settings.report_daily_limit
        self._retention_s = settings.report_retention_days * 86_400
        url = settings.database_url
        self._lock = threading.Lock()
        if url.startswith("sqlite:///"):
            self._kind = "sqlite"
            self._sqlite = sqlite3.connect(url[len("sqlite:///"):], check_same_thread=False,
                                           isolation_level=None)
            self._sqlite.execute("PRAGMA journal_mode=WAL")
            self._ph = "?"
        else:
            import psycopg  # imported lazily: optional dependency

            self._kind = "postgres"
            self._pg_url = url
            self._psycopg = psycopg
            self._ph = "%s"
        if url.startswith("sqlite:////tmp"):
            log.warning("report store uses ephemeral SQLite in /tmp - reports are lost "
                        "on restart; set TCS_DATABASE_URL to a Postgres database")

    # -- plumbing -------------------------------------------------------------
    def _q(self, sql: str) -> str:
        return sql.replace("?", self._ph)

    def _run(self, statements: Sequence[Tuple[str, Sequence]], fetch_last: bool = False) -> List[tuple]:
        """Execute statements atomically; return rows of the last one."""
        rows: List[tuple] = []
        if self._kind == "sqlite":
            with self._lock:
                cur = self._sqlite.cursor()
                try:
                    cur.execute("BEGIN IMMEDIATE")
                    for sql, params in statements:
                        cur.execute(self._q(sql), tuple(params))
                    if fetch_last:
                        rows = cur.fetchall()
                    cur.execute("COMMIT")
                except Exception:
                    cur.execute("ROLLBACK")
                    raise
            return rows
        with self._psycopg.connect(self._pg_url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                for sql, params in statements:
                    cur.execute(self._q(sql), tuple(params))
                if fetch_last:
                    rows = cur.fetchall()
        return rows

    def init_schema(self) -> None:
        self._run([(s, ()) for s in _SCHEMA])
        self.purge_expired()

    def purge_expired(self) -> None:
        cutoff = int(time.time()) - self._retention_s
        self._run([
            ("DELETE FROM report_links WHERE report_id IN "
             "(SELECT report_id FROM reports WHERE created_at < ?)", (cutoff,)),
            ("DELETE FROM reports WHERE created_at < ?", (cutoff,)),
            ("DELETE FROM slip_refs WHERE first_seen < ?", (cutoff,)),
        ])

    # -- hashing --------------------------------------------------------------
    def id_hash(self, ident: Identifier) -> str:
        msg = f"{ident.kind}:{ident.key}".encode("utf-8")
        return hmac.new(self._pepper, msg, hashlib.sha256).hexdigest()

    def subject_hash(self, purpose: str, value: str) -> str:
        msg = f"{purpose}:{value}".encode("utf-8")
        return hmac.new(self._pepper, msg, hashlib.sha256).hexdigest()

    # -- reputation lookup ------------------------------------------------------
    def reputation(self, idents: Iterable[Identifier]) -> Dict[str, Reputation]:
        idents = list(idents)[:24]
        if not idents:
            return {}
        hashes = {self.id_hash(i): i for i in idents}
        keys = list(hashes)
        marks = ",".join("?" * len(keys))

        direct = self._run([(
            f"SELECT l.id_hash, COUNT(DISTINCT r.reporter_hash), COUNT(DISTINCT r.report_id) "
            f"FROM report_links l JOIN reports r ON r.report_id = l.report_id "
            f"WHERE l.id_hash IN ({marks}) GROUP BY l.id_hash", keys)], fetch_last=True)
        direct_map = {row[0]: (int(row[1]), int(row[2])) for row in direct}

        out: Dict[str, Reputation] = {}
        for h, ident in hashes.items():
            linked = self._run([(
                "SELECT COUNT(DISTINCT l3.report_id) FROM report_links l1 "
                "JOIN report_links l2 ON l2.report_id = l1.report_id AND l2.id_hash <> ? "
                "JOIN report_links l3 ON l3.id_hash = l2.id_hash "
                "WHERE l1.id_hash = ? AND l3.report_id NOT IN "
                "(SELECT report_id FROM report_links WHERE id_hash = ?)",
                (h, h, h))], fetch_last=True)
            reporters, reports = direct_map.get(h, (0, 0))
            out[ident.kind + "|" + ident.key] = Reputation(
                reporters=reporters, reports=reports,
                linked_reports=int(linked[0][0]) if linked else 0)
        return out

    # -- reporting --------------------------------------------------------------
    def add_report(self, reporter_key: str, category: str, idents: List[Identifier]) -> str:
        if category not in REPORT_CATEGORIES:
            raise StoreError("INVALID_CATEGORY")
        if not idents:
            raise StoreError("NO_IDENTIFIER")
        reporter = self.subject_hash("reporter", reporter_key)
        now = int(time.time())

        recent = self._run([(
            "SELECT COUNT(*) FROM reports WHERE reporter_hash = ? AND created_at > ?",
            (reporter, now - 86_400))], fetch_last=True)
        if recent and int(recent[0][0]) >= self._daily_limit:
            raise StoreError("REPORT_LIMIT_REACHED")

        # one counted report per reporter per identifier
        id_hashes = [(self.id_hash(i), i.kind) for i in idents[:8]]
        marks = ",".join("?" * len(id_hashes))
        dup = self._run([(
            f"SELECT COUNT(*) FROM report_links l JOIN reports r ON r.report_id = l.report_id "
            f"WHERE r.reporter_hash = ? AND l.id_hash IN ({marks})",
            [reporter, *[h for h, _ in id_hashes]])], fetch_last=True)
        if dup and int(dup[0][0]) > 0:
            raise StoreError("ALREADY_REPORTED")

        report_id = secrets.token_hex(16)
        stmts = [("INSERT INTO reports (report_id, created_at, category, reporter_hash) "
                  "VALUES (?, ?, ?, ?)", (report_id, now, category, reporter))]
        stmts += [("INSERT INTO report_links (report_id, id_hash, kind) VALUES (?, ?, ?)",
                   (report_id, h, k)) for h, k in id_hashes]
        self._run(stmts)
        return report_id

    # -- slip re-use detection ----------------------------------------------------
    def slip_seen_elsewhere(self, ref: str, submitter_key: str) -> bool:
        """True if this transaction ref was submitted earlier by a DIFFERENT
        client (a victim re-checking their own slip is not a duplicate)."""
        ref_h = self.subject_hash("slipref", ref.upper())
        sub_h = self.subject_hash("submitter", submitter_key)
        rows = self._run([
            ("SELECT COUNT(*) FROM slip_refs WHERE ref_hash = ? AND submitter_hash <> ?",
             (ref_h, sub_h)),
        ], fetch_last=True)
        seen = bool(rows) and int(rows[0][0]) > 0
        insert = ("INSERT INTO slip_refs (ref_hash, submitter_hash, first_seen) VALUES (?, ?, ?) "
                  + ("ON CONFLICT DO NOTHING" if self._kind == "postgres" else ""))
        if self._kind == "sqlite":
            insert = insert.replace("INSERT INTO", "INSERT OR IGNORE INTO")
        self._run([(insert, (ref_h, sub_h, int(time.time())))])
        return seen
