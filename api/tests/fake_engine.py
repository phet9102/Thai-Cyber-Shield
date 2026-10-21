#!/usr/bin/env python3
"""Stand-in for the Ada engine that speaks the same stdin/stdout protocol.
Used only by the test-suite so the API can be tested without GNAT."""
import json
import sys

ENGINE = "tcs-ada/1.0"


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"sms", "url", "phone"}:
        print(json.dumps({"ok": False, "engine": ENGINE, "error": "USAGE"}))
        return 64
    mode = sys.argv[1]
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        print(json.dumps({"ok": False, "engine": ENGINE, "error": "INPUT_TOO_LONG"}))
        return 2
    text = raw.decode("utf-8")
    if "__hang__" in text:
        import time
        time.sleep(30)
    if "__garbage__" in text:
        print("not json")
        return 0
    score, findings, host = 0, [], None
    if mode == "phone" and text.replace(" ", "").startswith(("+697", "+698")):
        score, findings = 85, ["PH_UNASSIGNED_CC"]
    if mode == "url":
        host = "example.com"
        if "bit.ly" in text:
            score, findings, host = 20, ["URL_SHORTENER"], "bit.ly"
    if mode == "sms" and "ด่วน" in text:
        score, findings = 15, ["SMS_URGENCY"]
    level = "CRITICAL" if score >= 80 else "LOW" if score >= 15 else "SAFE"
    print(json.dumps({"ok": True, "engine": ENGINE, "mode": mode, "score": score,
                      "level": level, "findings": findings, "host": host}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
