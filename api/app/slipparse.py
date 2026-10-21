"""
Thai Cyber Shield API - transfer-slip field extraction.

Turns OCR text + decoded QR payloads into the strict key=value FACT sheet
consumed by the Ada TCS_Slip verifier. Python only *extracts*; every
decision (CRC validity, bank/ref cross-checks, time windows, scoring) is
made again by the engine.

Handles Thai slip conventions:
  * Buddhist-era years, 2-digit ("69") and 4-digit ("2569")
  * Thai month abbreviations ("ต.ค.") and full names, English months
  * amounts with thousands separators and "บาท"/"THB"
  * "เลขที่รายการ / รหัสอ้างอิง / Ref / Transaction ID" labels
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

BANGKOK = timezone(timedelta(hours=7))   # Thailand has no DST

# Ordered: more specific names first. Values are TCS_Slip bank tokens.
_BANK_PATTERNS: List[Tuple[str, Tuple[str, ...]]] = [
    ("TRUEMONEY", ("truemoney", "true money", "ทรูมันนี่", "ทรูมันนี")),
    ("KBANK", ("กสิกร", "kasikorn", "k plus", "kplus", "kbank")),
    ("SCB", ("ไทยพาณิชย์", "scb easy", "scb")),
    ("KTB", ("กรุงไทย", "krungthai", "krung thai", "ktb", "เป๋าตัง")),
    ("BBL", ("ธนาคารกรุงเทพ", "ธ.กรุงเทพ", "bangkok bank", "bualuang", "บัวหลวง")),
    ("BAY", ("กรุงศรี", "krungsri", "kma")),
    ("TTB", ("ทีทีบี", "ttb", "ทหารไทยธนชาต")),
    ("GSB", ("ออมสิน", "mymo", "gsb")),
    ("BAAC", ("ธ.ก.ส", "ธกส", "baac")),
    ("GHB", ("อาคารสงเคราะห์", "ghb")),
    ("KKP", ("เกียรตินาคิน", "kkp")),
    ("CIMB", ("ซีไอเอ็มบี", "cimb")),
    ("UOB", ("ยูโอบี", "uob")),
    ("TISCO", ("ทิสโก้", "tisco")),
    ("LHB", ("แลนด์ แอนด์ เฮ้าส์", "lh bank", "lhbank")),
]

_THAI_MONTHS = {
    "ม.ค.": 1, "มกราคม": 1, "ก.พ.": 2, "กุมภาพันธ์": 2, "มี.ค.": 3, "มีนาคม": 3,
    "เม.ย.": 4, "เมษายน": 4, "พ.ค.": 5, "พฤษภาคม": 5, "มิ.ย.": 6, "มิถุนายน": 6,
    "ก.ค.": 7, "กรกฎาคม": 7, "ส.ค.": 8, "สิงหาคม": 8, "ก.ย.": 9, "กันยายน": 9,
    "ต.ค.": 10, "ตุลาคม": 10, "พ.ย.": 11, "พฤศจิกายน": 11, "ธ.ค.": 12, "ธันวาคม": 12,
}
_EN_MONTHS = {m: i + 1 for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}

_THAI_DIGITS = str.maketrans("๐๑๒๓๔๕๖๗๘๙", "0123456789")

# Label only. The value is searched in a window AFTER the label, because on
# real slips (e.g. K PLUS) the value sits on the next line and OCR often
# merges unrelated text (the "สแกนตรวจสอบสลิป" caption under the QR) in
# between. Thai OCR also drops tone marks ("เลขทีรายการ"), hence the `?`.
_REF_LABEL = re.compile(
    r"(เลขที่?\s*รายการ|รหัส\s*อ้างอิง|เลขที่?\s*อ้างอิง|หมายเลข\s*อ้างอิง|รหัส\s*รายการ|"
    r"transaction\s*id|trans(?:action)?\s*ref|ref(?:erence)?\s*(?:no\.?|id)?)\s*[:：]?",
    re.IGNORECASE,
)
_REF_TOKEN = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9]{10,40})(?![A-Za-z0-9])")
_REF_WINDOW = 200          # characters after the label to search for the value

# Bank codes used in tag 00/01 of the slip-verification mini-QR.
_QR_BANK_CODES = {
    "002": "BBL", "004": "KBANK", "006": "KTB", "011": "TTB", "014": "SCB",
    "022": "CIMB", "024": "UOB", "025": "BAY", "030": "GSB", "033": "GHB",
    "034": "BAAC", "067": "TISCO", "069": "KKP", "073": "LHB",
}

# K PLUS reference: 0 + 2 digits, day-of-year (3), HHMMSS (6), letters ...
# Verified against one real K PLUS slip (ref 016281125152BPM14801 printed on
# a slip dated 8 Oct 2026 12:51 -> day 281, 12:51:52). Other banks: unknown
# until real samples are collected - do NOT add formats without a sample.
_KBANK_REF = re.compile(r"^0\d{2}(\d{3})([01]\d|2[0-3])([0-5]\d)([0-5]\d)[A-Z]")
_AMOUNT_LABEL = re.compile(
    r"(จำนวนเงิน|จำนวน|ยอดเงิน|ยอดโอน|amount)\s*[:：]?\s*"
    r"([0-9]{1,3}(?:,[0-9]{3}){0,4}(?:\.[0-9]{1,2})?|[0-9]{1,11}(?:\.[0-9]{1,2})?)",
    re.IGNORECASE,
)
_AMOUNT_BAHT = re.compile(
    r"([0-9]{1,3}(?:,[0-9]{3}){0,4}\.[0-9]{2}|[0-9]{1,11}\.[0-9]{2})\s*(?:บาท|thb|฿)?",
    re.IGNORECASE,
)
_TIME = re.compile(r"(?<!\d)([01]?\d|2[0-3])[:.]([0-5]\d)(?:[:.][0-5]\d)?(?!\d)")
_DATE_NUMERIC = re.compile(r"(?<!\d)(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})(?!\d)")
_DATE_WORD = re.compile(r"(?<!\d)(\d{1,2})\s*([^\s\d]{2,12})\s*(\d{2,4})(?!\d)")


def _abbr_pattern(abbr: str) -> str:
    # "ต.ค." -> "ต\s*\.?\s*ค\s*\.?" : OCR splits or drops the dots ("ต. ค.", "ต.ค", "ตค")
    letters = [ch for ch in abbr if ch != "."]
    return r"\s*\.?\s*".join(re.escape(ch) for ch in letters) + r"\s*\.?"


_THAI_ABBR = {k: v for k, v in _THAI_MONTHS.items() if k.endswith(".")}
_DATE_THAI_ABBR = re.compile(
    r"(?<!\d)(\d{1,2})\s*(" + "|".join(
        _abbr_pattern(k) for k in sorted(_THAI_ABBR, key=len, reverse=True)
    ) + r")\s*(\d{2,4})(?!\d)"
)


@dataclass
class SlipFacts:
    bank: str = "UNKNOWN"
    ref: Optional[str] = None
    amount: Optional[str] = None          # normalised "1500.00"
    amount_raw: Optional[str] = None      # as printed, for the consistency check
    when: Optional[datetime] = None
    when_from_ref: bool = False           # time derived from the reference, not printed text
    qr: Optional[str] = None
    qr_bank: Optional[str] = None         # from a CRC-valid QR only
    qr_ref: Optional[str] = None          # from a CRC-valid QR only


def _year(y: int) -> Optional[int]:
    if y < 100:                       # 2-digit: Thai slips use BE ("69" = 2569)
        y = 2500 + y
    if y > 2400:                      # Buddhist era -> Gregorian
        y -= 543
    return y if 2000 <= y <= 2100 else None


def detect_bank(text: str) -> str:
    lines = [ln.strip().lower() for ln in text.splitlines() if ln.strip()]
    head = " ".join(lines[:4])
    # 1) a bank named in the header (app branding) wins
    for token, pats in _BANK_PATTERNS:
        if any(p in head for p in pats):
            return token
    # 2) otherwise only if exactly one bank is mentioned anywhere
    full = " ".join(lines)
    hits = {token for token, pats in _BANK_PATTERNS if any(p in full for p in pats)}
    return hits.pop() if len(hits) == 1 else "UNKNOWN"


def _parse_datetime(text: str) -> Optional[datetime]:
    t = text.translate(_THAI_DIGITS)
    day = month = year = None

    m = _DATE_NUMERIC.search(t)
    a = _DATE_THAI_ABBR.search(t)
    if m:
        day, month, year = int(m.group(1)), int(m.group(2)), _year(int(m.group(3)))
    elif a:
        abbr = re.sub(r"[\s.]", "", a.group(2))
        month = next(v for k, v in _THAI_ABBR.items() if k.replace(".", "") == abbr)
        day, year = int(a.group(1)), _year(int(a.group(3)))
    else:
        for m in _DATE_WORD.finditer(t):
            word = m.group(2).strip().lower().replace(" ", "")
            mon = _THAI_MONTHS.get(word) or _EN_MONTHS.get(word[:3])
            if not mon:
                for k, v in _THAI_MONTHS.items():       # OCR often drops the dots
                    if word == k.replace(".", ""):
                        mon = v
                        break
            if mon:
                day, month, year = int(m.group(1)), mon, _year(int(m.group(3)))
                break
    if not (day and month and year):
        return None

    hh = mm = 0
    tm = _TIME.search(t)
    if tm:
        hh, mm = int(tm.group(1)), int(tm.group(2))
    try:
        return datetime(year, month, day, hh, mm, tzinfo=BANGKOK)
    except ValueError:
        return None


def _normalise_amount(raw: str) -> Optional[str]:
    v = raw.replace(",", "")
    if not re.fullmatch(r"\d{1,11}(\.\d{1,2})?", v):
        return None
    if "." in v:
        whole, frac = v.split(".")
        return f"{int(whole)}.{frac.ljust(2, '0')}"
    return f"{int(v)}.00"


def _find_ref(t: str) -> Optional[str]:
    """First reference-like token (>= 6 digits, not a masked account) that
    follows a reference label within _REF_WINDOW characters."""
    for lab in _REF_LABEL.finditer(t):
        window = t[lab.end(): lab.end() + _REF_WINDOW]
        for tok in _REF_TOKEN.finditer(window):
            v = tok.group(1)
            if sum(ch.isdigit() for ch in v) >= 6 and "xx" not in v.lower():   # "xx" = masked
                return v
    return None


def time_from_kbank_ref(ref: str, now: datetime) -> Optional[datetime]:
    """Most recent date (<= now + 1 day) whose day-of-year matches the ref."""
    m = _KBANK_REF.match(ref.upper())
    if not m:
        return None
    doy, hh, mm = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not 1 <= doy <= 366:
        return None
    now = now.astimezone(BANGKOK)
    for year in (now.year, now.year - 1):
        try:
            d = datetime(year, 1, 1, hh, mm, tzinfo=BANGKOK) + timedelta(days=doy - 1)
        except ValueError:
            continue
        if d.year == year and d <= now + timedelta(days=1):
            return d
    return None


def extract_slip(text: str, qr_payloads: List[str],
                 now: Optional[datetime] = None) -> SlipFacts:
    facts = SlipFacts()
    t = text.translate(_THAI_DIGITS)
    facts.bank = detect_bank(t)
    facts.ref = _find_ref(t)

    m = _AMOUNT_LABEL.search(t)
    raw = m.group(2) if m else None
    if raw is None:
        cands = [c.group(1) for c in _AMOUNT_BAHT.finditer(t)]
        if cands:   # largest decimal amount on the slip
            raw = max(cands, key=lambda c: float(c.replace(",", "")))
    if raw:
        facts.amount_raw = raw
        facts.amount = _normalise_amount(raw)

    facts.when = _parse_datetime(t)

    for p in qr_payloads:                 # prefer a slip-verification QR
        if p.startswith("00") and "5102TH" in p:
            facts.qr = p
            break
    if facts.qr is None and qr_payloads:
        facts.qr = qr_payloads[0]

    # Facts proven by a CRC-valid QR. Kept SEPARATE from the OCR fields so
    # the engine's QR-vs-printed cross-checks stay meaningful; they are used
    # for display, duplicate detection and the time fallback only.
    info = parse_slip_qr(facts.qr) if facts.qr else None
    if info and info["crc_ok"]:
        facts.qr_bank = _QR_BANK_CODES.get(info["bank_code"])
        facts.qr_ref = info["ref"]

    # Printed date unreadable -> derive it from a K PLUS reference so the
    # engine's stale/future-slip checks still run.
    if facts.when is None:
        bank = facts.bank if facts.bank != "UNKNOWN" else facts.qr_bank
        ref = facts.qr_ref or facts.ref
        if bank == "KBANK" and ref:
            facts.when = time_from_kbank_ref(ref, now or datetime.now(BANGKOK))
            facts.when_from_ref = facts.when is not None
    return facts


def _clean_value(v: str, allowed: str, max_len: int) -> Optional[str]:
    v = "".join(ch for ch in v if ch in allowed)[:max_len]
    return v or None


_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def build_fact_sheet(facts: SlipFacts, *, expected: Optional[str], edited: bool,
                     inconsistent: bool, duplicate: bool, ocr_conf: int,
                     now: Optional[datetime] = None) -> str:
    """Serialise facts for the engine. Only whitelisted ASCII survives."""
    now = now or datetime.now(BANGKOK)
    lines: Dict[str, str] = {"bank": facts.bank}
    if facts.ref:
        v = _clean_value(facts.ref, _ALNUM, 40)
        if v:
            lines["ref"] = v
    if facts.amount:
        lines["amount"] = facts.amount
    if expected:
        e = _normalise_amount(expected)
        if e:
            lines["expected"] = e
    if facts.when:
        lines["time"] = facts.when.strftime("%Y%m%d%H%M")
    lines["now"] = now.astimezone(BANGKOK).strftime("%Y%m%d%H%M")
    if facts.qr:
        q = "".join(ch for ch in facts.qr if 0x21 <= ord(ch) <= 0x7E)[:512]
        if q:
            lines["qr"] = q
    if edited:
        lines["edited"] = "1"
    if inconsistent:
        lines["inconsistent"] = "1"
    if duplicate:
        lines["dup"] = "1"
    lines["ocr_conf"] = str(max(0, min(100, ocr_conf)))
    return "".join(f"{k}={v}\n" for k, v in lines.items())


# ---------------------------------------------------------------------------
# Reference implementation of the mini-QR checks (mirrors TCS_Slip) - used
# for display and as a test oracle for the Ada engine.
# ---------------------------------------------------------------------------
def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def parse_slip_qr(q: str) -> Optional[dict]:
    pos, out, crc_start = 0, {}, None
    while pos < len(q):
        head = q[pos:pos + 4]
        if len(head) < 4 or not head.isdigit():
            return None
        tag, ln = int(head[:2]), int(head[2:])
        val = q[pos + 4: pos + 4 + ln]
        if len(val) != ln:
            return None
        if tag == 0:
            sp = 0
            while sp < len(val):
                sh = val[sp:sp + 4]
                if len(sh) < 4 or not sh.isdigit():
                    return None
                st, sl = int(sh[:2]), int(sh[2:])
                sv = val[sp + 4: sp + 4 + sl]
                if len(sv) != sl:
                    return None
                if st == 1:
                    out["bank_code"] = sv
                elif st == 2:
                    out["ref"] = sv
                sp += 4 + sl
        elif tag == 91:
            if ln != 4 or pos + 4 + ln != len(q):
                return None
            crc_start = pos + 4
        pos += 4 + ln
    if crc_start is None or "bank_code" not in out or "ref" not in out:
        return None
    out["crc_ok"] = format(crc16_ccitt_false(q[:crc_start].encode()), "04X") == q[crc_start:].upper()
    return out
