"""Security-focused API tests.   Run:  cd api && pytest -q"""
import os
import stat
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
FAKE = HERE / "fake_engine.py"
FAKE.chmod(FAKE.stat().st_mode | stat.S_IXUSR)
FAKE.chmod(FAKE.stat().st_mode & ~(stat.S_IWGRP | stat.S_IWOTH))

os.environ.update(
    TCS_ENV="test",
    TCS_ENGINE_PATH=str(FAKE),
    TCS_ENGINE_USE_PRLIMIT="false",
    TCS_ALLOWED_ORIGINS="https://app.example",
    TCS_ALLOWED_HOSTS="testserver",
    TCS_IP_BURST="1000",
    TCS_ENGINE_TIMEOUT_S="1.0",
    TCS_DATABASE_URL="sqlite:///" + str(HERE / "test_reports.db"),
    TCS_OCR_LANGS="eng",
)
for _p in HERE.glob("test_reports.db*"):
    _p.unlink()
sys.path.insert(0, str(HERE.parent))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

J = {"Content-Type": "application/json"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_phone_spoof_detected(client):
    r = client.post("/api/v1/analyze/phone", json={"phone": "+697 123 456 789"})
    assert r.status_code == 200
    assert r.json()["level"] == "CRITICAL"


def test_security_headers_present(client):
    r = client.get("/api/health")
    h = r.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert "server" not in h


def test_validation_error_does_not_reflect_input(client):
    payload = "<script>alert(1)</script>"
    r = client.post("/api/v1/analyze/phone", json={"phone": payload})
    assert r.status_code == 422
    assert "script" not in r.text


def test_extra_fields_rejected(client):
    r = client.post("/api/v1/analyze/sms", json={"message": "hi", "admin": True})
    assert r.status_code == 422


def test_type_confusion_rejected(client):
    r = client.post("/api/v1/analyze/sms", json={"message": 12345})
    assert r.status_code == 422


def test_form_post_rejected(client):
    r = client.post("/api/v1/analyze/sms", content=b"message=x",
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415


def test_oversized_body_rejected(client):
    r = client.post("/api/v1/analyze/sms", content=b"{" + b" " * 40_000 + b"}", headers=J)
    assert r.status_code == 413


def test_url_markup_rejected(client):
    r = client.post("/api/v1/analyze/url", json={"url": 'https://a.com/"><svg onload=alert(1)>'})
    assert r.status_code == 422


def test_shell_metacharacters_are_inert(client, tmp_path):
    marker = tmp_path / "pwned"
    r = client.post("/api/v1/analyze/sms", json={"message": f"x; touch {marker} && $(touch {marker})"})
    assert r.status_code == 200
    assert not marker.exists()


def test_engine_garbage_output_is_contained(client):
    r = client.post("/api/v1/analyze/sms", json={"message": "__garbage__"})
    assert r.status_code == 503
    assert r.json()["error"] == "SERVICE_UNAVAILABLE"


def test_engine_timeout_is_contained(client):
    r = client.post("/api/v1/analyze/sms", json={"message": "__hang__"})
    assert r.status_code == 503


def test_cors_unknown_origin_not_allowed(client):
    r = client.options("/api/v1/analyze/sms", headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "POST"})
    assert r.headers.get("access-control-allow-origin") is None


def test_bad_host_header_rejected(client):
    r = client.get("/api/health", headers={"Host": "evil.example"})
    assert r.status_code == 400


def test_rate_limit_token_bucket():
    import asyncio
    from app.config import load_settings
    from app.ratelimit import RateLimiter

    os.environ["TCS_IP_BURST"] = "3"
    lim = RateLimiter(load_settings())
    os.environ["TCS_IP_BURST"] = "1000"

    async def burst():
        return [(await lim.check("1.2.3.4")).allowed for _ in range(5)]

    assert asyncio.run(burst()) == [True, True, True, False, False]


def test_xff_spoofing_ignored_without_trusted_proxy():
    from app.ratelimit import client_key
    assert client_key("203.0.113.9", ["1.1.1.1"], ()) == "203.0.113.9"


def test_xff_right_to_left_with_trusted_proxy():
    import ipaddress
    from app.ratelimit import client_key
    trusted = (ipaddress.ip_network("10.0.0.0/8"),)
    # attacker prepends a fake hop; real client is the right-most untrusted
    assert client_key("10.0.0.5", ["6.6.6.6, 198.51.100.7, 10.0.0.9"], trusted) == "198.51.100.7"


# ---------------------------------------------------------------------------
# v2: trade, reports, uploads
# ---------------------------------------------------------------------------
def test_trade_and_report_correlation(client):
    chat = "โอนก่อนนะ ไม่รับกลาง โทร 081-234-5678"
    r = client.post("/api/v1/analyze/trade", json={"chat": chat})
    assert r.status_code == 200
    assert any(i["kind"] == "phone" for i in r.json()["identifiers"])

    for ip in ("10.1.1.1", "10.1.1.2", "10.1.1.3"):
        rep = client.post("/api/v1/reports",
                          json={"category": "item_trade", "phone": "0812345678", "consent": True},
                          headers={"X-Forwarded-For": ip})
        assert rep.status_code in (201, 409)

    r2 = client.post("/api/v1/analyze/trade", json={"chat": chat})
    body = r2.json()
    phone = [i for i in body["identifiers"] if i["kind"] == "phone"][0]
    assert phone["display"].endswith("678") and "081" not in phone["display"]
    assert phone["reporters"] >= 1


def test_report_requires_consent(client):
    r = client.post("/api/v1/reports", json={"category": "other", "phone": "0812345678"})
    assert r.status_code == 422


def test_report_rejects_unknown_category(client):
    r = client.post("/api/v1/reports",
                    json={"category": "revenge", "phone": "0812345678", "consent": True})
    assert r.status_code == 422


def _png() -> bytes:
    import io
    from PIL import Image, ImageDraw
    img = Image.new("RGB", (600, 300), "white")
    ImageDraw.Draw(img).text((20, 20), "Amount 1,500.00 THB", fill="black")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def test_upload_requires_custom_header(client):
    r = client.post("/api/v1/analyze/slip", files={"file": ("s.png", _png(), "image/png")})
    assert r.status_code == 415


def test_upload_rejects_non_image(client):
    r = client.post("/api/v1/analyze/slip", files={"file": ("s.png", b"<svg onload=alert(1)>", "image/png")},
                    headers={"X-TCS-Client": "web"})
    assert r.status_code == 422
    assert "svg" not in r.text


def test_upload_rejects_bad_expected_amount(client):
    r = client.post("/api/v1/analyze/slip", files={"file": ("s.png", _png(), "image/png")},
                    data={"expected_amount": "1;rm -rf /"}, headers={"X-TCS-Client": "web"})
    assert r.status_code == 422
