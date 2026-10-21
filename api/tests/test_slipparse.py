"""Slip extraction regression tests.

Layout mirrors a real K PLUS top-up slip (8 Oct 2569 12:51, 50.00 THB,
ref 016281125152BPM14801) that the v2 parser failed on: the ref value sits
two lines below its label with the QR caption merged in between, and Thai
OCR splits the month abbreviation. Personal names/accounts are replaced.

NOTE: QR_KPLUS is SYNTHETIC (built with the real ref + KBank code 004).
Replace it with the real payload of a scanned slip when available.
"""
from datetime import datetime

from app.slipparse import (BANGKOK, build_fact_sheet, crc16_ccitt_false,
                           extract_slip, parse_slip_qr, time_from_kbank_ref)

NOW = datetime(2026, 10, 22, 0, 38, tzinfo=BANGKOK)
REF = "016281125152BPM14801"


def _qr(bank: str, ref: str) -> str:
    sub = f"0103{bank}02{len(ref):02d}{ref}"
    body = f"00{len(sub):02d}{sub}5102TH9104"
    return body + format(crc16_ccitt_false(body.encode()), "04X")


QR_KPLUS = _qr("004", REF)

OCR_KPLUS = """เติมเงินสำเร็จ
8 ต. ค. 69 12:51 น.
นาย ทดสอบ ท
ธ.กสิกรไทย
xxx-x-x1234-x
พร้อมเพย์
อี-วอลเล็ต /
G-Wallet
006-xxxxxxxx-0000
จำนวน:
50.00 บาท
ค่าธรรมเนียม:
0.00 บาท
เลขทีรายการ:
สแกน
016281125152BPM14801 ตรวจสอบสลิป
"""


def test_synthetic_qr_is_valid():
    info = parse_slip_qr(QR_KPLUS)
    assert info and info["crc_ok"] and info["bank_code"] == "004" and info["ref"] == REF


def test_ref_found_below_label_with_noise_between():
    f = extract_slip(OCR_KPLUS, [], now=NOW)
    assert f.ref == REF


def test_split_thai_month_abbreviation():
    f = extract_slip(OCR_KPLUS, [], now=NOW)
    assert f.when == datetime(2026, 10, 8, 12, 51, tzinfo=BANGKOK)
    assert not f.when_from_ref


def test_amount_and_bank():
    f = extract_slip(OCR_KPLUS, [], now=NOW)
    assert f.amount == "50.00" and f.bank == "KBANK"


def test_qr_fills_bank_and_ref_when_ocr_is_garbage():
    f = extract_slip("ooo garbled ooo\n50.00", [QR_KPLUS], now=NOW)
    assert f.bank == "UNKNOWN"            # OCR field stays honest for the engine
    assert f.qr_bank == "KBANK" and f.qr_ref == REF
    assert f.ref is None


def test_time_derived_from_kbank_ref_when_date_unreadable():
    f = extract_slip("ooo garbled ooo\n50.00", [QR_KPLUS], now=NOW)
    assert f.when_from_ref
    assert f.when == datetime(2026, 10, 8, 12, 51, tzinfo=BANGKOK)
    sheet = build_fact_sheet(f, expected="50", edited=False, inconsistent=False,
                             duplicate=False, ocr_conf=80, now=NOW)
    assert "time=202610081251\n" in sheet  # engine will now flag "> 3 days old"


def test_invalid_crc_qr_is_not_trusted():
    bad = QR_KPLUS[:-4] + "0000"
    f = extract_slip("garbled", [bad], now=NOW)
    assert f.qr_bank is None and f.qr_ref is None and f.when is None


def test_kbank_ref_year_rollover_and_rejects():
    jan = datetime(2027, 1, 2, 9, 0, tzinfo=BANGKOK)
    assert time_from_kbank_ref(REF, jan) == datetime(2026, 10, 8, 12, 51, tzinfo=BANGKOK)
    assert time_from_kbank_ref("016999125152BPM1", NOW) is None     # day 999
    assert time_from_kbank_ref("016281255152BPM1", NOW) is None     # hour 25
    assert time_from_kbank_ref("ABCDEFGHIJKL", NOW) is None


def test_masked_account_not_taken_as_ref():
    f = extract_slip("เลขที่รายการ:\nxxx-x-x1234-x 1234567890xx\nABC123456789", [], now=NOW)
    assert f.ref == "ABC123456789"
