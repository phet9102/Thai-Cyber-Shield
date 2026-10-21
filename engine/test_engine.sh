#!/usr/bin/env bash
# Smoke tests for the Ada engine. Run after: gprbuild -P tcs_engine.gpr
set -euo pipefail
BIN="$(dirname "$0")/bin/tcs_engine"

run() {  # mode, input
  printf '%s' "$2" | "$BIN" "$1" || true
}

echo "== SMS =="
run sms 'ด่วน! บัญชีของท่านถูกระงับ กรุณายืนยันตัวตนที่ https://bit.ly/abc ภายในวันนี้'
run sms 'โ อ น เ งิ น ด่ว น แอดไลน์ @abc รับเครดิตฟรี 500'
run sms 'พรุ่งนี้ประชุม 10 โมงนะครับ'
run sms '%n%n%s%s <script>alert(1)</script>'

echo "== URL =="
run url 'https://www.scb.co.th/th/personal-banking.html'
run url 'http://scb-th-update.top/login'
run url 'https://krungthai.com@evil.example/verify'
run url 'https://xn--scb-xyz.com'
run url 'http://3232235777/app.apk'
run url 'javascript:alert(1)'
run url 'https://gov.th.refund-tax.cc/'

echo "== PHONE =="
run phone '+697 123 456 789'
run phone '6981234567'
run phone '081-234-5678'
run phone '+66 0812345678'
run phone '+855 12 345 678'
run phone '๐๘๑๒๓๔๕๖๗๘'
run phone '1900-123-456'
run phone '081<script>'

echo "== Rejections =="
printf 'abc\x00def' | "$BIN" sms || echo "exit=$?"
printf '\xc0\xaf'    | "$BIN" url || echo "exit=$?"
head -c 9000 /dev/zero | tr '\0' 'a' | "$BIN" sms || echo "exit=$?"
"$BIN" 'sms; rm -rf /' </dev/null || echo "exit=$?"
