"""
Thai Cyber Shield API - identifier extraction & canonicalisation.

Pulls the identifiers a scammer must expose to get paid or contacted
(phone numbers, bank account numbers, e-mail addresses, Facebook profile /
page / group / item links, other URLs) out of free text - typed chat,
OCR'd screenshots or slips - and canonicalises them so that the SAME
identifier written differently ("081-234-5678", "+66812345678",
"๐๘๑ ๒๓๔ ๕๖๗๘") always maps to the SAME key.

Canonical keys are never stored: store.py turns them into keyed HMACs.
Display values are masked so a screenshot of our UI cannot leak them.

Every regex here is linear (no nested quantifiers) and input is capped
before matching -> no ReDoS.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

MAX_SCAN_CHARS = 12_000
MAX_PER_KIND = 8

_THAI_DIGITS = str.maketrans("๐๑๒๓๔๕๖๗๘๙", "0123456789")
_FULLWIDTH = {i: i - 0xFEE0 for i in range(0xFF01, 0xFF5F)}

_PHONE_RE = re.compile(r"(?<![\w.@/])(\+?\d[\d\- ()]{6,18}\d)(?![\w@])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}")
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]{2,2048}", re.IGNORECASE)
_FB_BARE_RE = re.compile(
    r"(?<![\w.])(?:m\.|web\.|www\.|mbasic\.)?(?:facebook\.com|fb\.com|fb\.me)/[^\s<>\"'`]{1,512}",
    re.IGNORECASE,
)

FB_HOSTS = ("facebook.com", "fb.com", "fb.me", "fb.watch", "messenger.com")
_FB_RESERVED = {
    "groups", "share", "marketplace", "watch", "permalink.php", "story.php",
    "photo.php", "photo", "photos", "events", "pages", "login", "login.php",
    "l.php", "reel", "reels", "hashtag", "people", "profile.php", "sharer",
    "sharer.php", "dialog", "help", "policies", "settings", "home.php",
}


@dataclass(frozen=True)
class Identifier:
    kind: str          # phone | bank_account | email | facebook | url
    key: str           # canonical value (hashed before storage, never logged)
    display: str       # masked, safe to show


def normalise_text(text: str) -> str:
    return text[:MAX_SCAN_CHARS].translate(_THAI_DIGITS).translate(_FULLWIDTH)


# ---------------------------------------------------------------------------
# Phones / bank accounts
# ---------------------------------------------------------------------------
def canonical_phone(raw: str) -> Optional[str]:
    s = raw.translate(_THAI_DIGITS).translate(_FULLWIDTH).strip()
    plus = s.startswith("+")
    digits = re.sub(r"\D", "", s)
    if plus:
        if not 7 <= len(digits) <= 15:
            return None
        if digits.startswith("660"):                       # +66 0xx -> +66 xx
            digits = "66" + digits[3:]
        return "+" + digits
    if digits.startswith("00") and 9 <= len(digits) <= 17:
        return "+" + digits[2:]
    if digits.startswith("0") and len(digits) in (9, 10):
        return "+66" + digits[1:]
    if digits.startswith("66") and len(digits) == 11:
        return "+" + digits
    if digits.startswith("69") and len(digits) >= 9 and digits[2] in "3456789":
        return "+" + digits                                # spoofed 69x shown without '+'
    return None


def _is_thai_mobile_local(digits: str) -> bool:
    return len(digits) == 10 and digits[0] == "0" and digits[1] in "689"


def mask_phone(canon: str) -> str:
    return canon[:4] + "•" * max(0, len(canon) - 7) + canon[-3:]


def mask_account(digits: str) -> str:
    return "•" * max(0, len(digits) - 4) + digits[-4:]


# ---------------------------------------------------------------------------
# Facebook canonicalisation
# ---------------------------------------------------------------------------
def _host_is(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def canonical_facebook(url: str) -> Optional[str]:
    """Return a stable key such as fb:id:1000..., fb:user:somename,
    fb:group:123, fb:item:456 - or None when the link is not Facebook."""
    u = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", u):
        u = "https://" + u
    try:
        parts = urlsplit(u)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not any(_host_is(host, d) for d in FB_HOSTS):
        return None

    segs = [s for s in parts.path.split("/") if s]
    qs = parse_qs(parts.query, keep_blank_values=False, max_num_fields=20)

    if segs and segs[0].lower() == "profile.php":
        pid = (qs.get("id") or [""])[0]
        return f"fb:id:{pid}" if pid.isdigit() and len(pid) <= 20 else None
    if len(segs) >= 2 and segs[0].lower() == "groups":
        return f"fb:group:{segs[1].lower()[:100]}"
    if len(segs) >= 3 and segs[0].lower() == "marketplace" and segs[1].lower() == "item":
        item = segs[2]
        return f"fb:item:{item}" if item.isdigit() else None
    if segs and segs[0].lower() == "share":
        return "fb:share:" + "/".join(segs[1:3]).lower()[:120]
    if segs and segs[0].lower() not in _FB_RESERVED:
        name = segs[0].lower()
        if re.fullmatch(r"[a-z0-9.\-]{2,80}", name):
            return f"fb:user:{name.replace('.', '')}"      # FB ignores dots
    return None


# ---------------------------------------------------------------------------
# E-mail
# ---------------------------------------------------------------------------
_GMAIL = {"gmail.com", "googlemail.com"}


def canonical_email(raw: str) -> Optional[str]:
    e = raw.strip().lower()
    if e.count("@") != 1:
        return None
    local, domain = e.split("@")
    if not local or not domain or len(local) > 64 or len(domain) > 253:
        return None
    local = local.split("+", 1)[0]                          # sub-addressing
    if domain in _GMAIL:
        local = local.replace(".", "")                     # gmail ignores dots
        domain = "gmail.com"
    return f"{local}@{domain}"


def mask_email(canon: str) -> str:
    local, domain = canon.split("@", 1)
    return (local[:2] + "•" * max(1, len(local) - 2)) + "@" + domain


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
def extract_identifiers(text: str) -> List[Identifier]:
    t = normalise_text(text)
    found: Dict[str, Identifier] = {}
    per_kind: Dict[str, int] = {}

    def add(ident: Identifier) -> None:
        k = ident.kind + "|" + ident.key
        if k in found or per_kind.get(ident.kind, 0) >= MAX_PER_KIND:
            return
        per_kind[ident.kind] = per_kind.get(ident.kind, 0) + 1
        found[k] = ident

    # URLs first, so digits inside them are not mistaken for phones
    url_spans = []
    for m in list(_URL_RE.finditer(t)) + list(_FB_BARE_RE.finditer(t)):
        url_spans.append(m.span())
        raw = m.group(0).rstrip(".,);]")
        fb = canonical_facebook(raw)
        if fb:
            add(Identifier("facebook", fb, raw[:120]))
        else:
            add(Identifier("url", raw.lower()[:2048], raw[:120]))

    email_spans = []
    for m in _EMAIL_RE.finditer(t):
        email_spans.append(m.span())
        canon = canonical_email(m.group(0))
        if canon:
            add(Identifier("email", canon, mask_email(canon)))

    def inside(span, spans) -> bool:
        return any(a <= span[0] and span[1] <= b for a, b in spans)

    for m in _PHONE_RE.finditer(t):
        if inside(m.span(), url_spans) or inside(m.span(), email_spans):
            continue
        raw = m.group(1)
        digits = re.sub(r"\D", "", raw)
        if raw.startswith("+") or _is_thai_mobile_local(digits) or \
                (digits.startswith("0") and len(digits) == 9) or digits.startswith("69"):
            canon = canonical_phone(raw)
            if canon:
                add(Identifier("phone", canon, mask_phone(canon)))
        elif 10 <= len(digits) <= 12:
            add(Identifier("bank_account", digits, mask_account(digits)))

    return list(found.values())


def identifier_from_field(kind: str, value: str) -> Optional[Identifier]:
    """Canonicalise one explicitly typed field (report form / single lookups)."""
    v = value.strip()
    if not v:
        return None
    if kind == "phone":
        c = canonical_phone(v)
        return Identifier("phone", c, mask_phone(c)) if c else None
    if kind == "bank_account":
        d = re.sub(r"\D", "", v.translate(_THAI_DIGITS))
        return Identifier("bank_account", d, mask_account(d)) if 10 <= len(d) <= 15 else None
    if kind == "email":
        c = canonical_email(v)
        return Identifier("email", c, mask_email(c)) if c else None
    if kind == "facebook":
        c = canonical_facebook(v)
        return Identifier("facebook", c, v[:120]) if c else None
    if kind == "url":
        return Identifier("url", v.lower()[:2048], v[:120])
    return None
