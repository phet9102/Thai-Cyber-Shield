# Thai Cyber Shield v2

ระบบตรวจแชทซื้อขาย สลิปโอนเงิน ลิงก์ Facebook อีเมล เบอร์โทร และ SMS ที่น่าสงสัยสำหรับคนไทย

| ส่วน | เทคโนโลยี | โฟลเดอร์ |
|---|---|---|
| Secure Core Engine | Ada 2012 / SPARK (7 โหมด) | `engine/` |
| API + Vision/OCR + Report store | Python 3.12 / FastAPI / Tesseract / zbar | `api/` |
| Frontend | HTML / Tailwind CSS / Vanilla JS (Vercel) | `frontend/` |

รายละเอียดสถาปัตยกรรม SPARK Contracts, กลไก OSINT และกลไกความปลอดภัยทั้งหมดอยู่ใน [SECURITY.md](SECURITY.md)

## Engine

```bash
cd engine
gprbuild -P tcs_engine.gpr -XBUILD=release -p
gnatprove -P tcs_engine.gpr --level=2
./test_engine.sh
```

โปรโตคอล: `printf '%s' "<input>" | bin/tcs_engine sms|url|phone|trade|slip|social|email`

## API endpoints

| Method | Path | Body |
|---|---|---|
| POST | `/api/v1/analyze/trade` | `{"chat": "..."}` |
| POST | `/api/v1/analyze/chat-image` | multipart `file` + header `X-TCS-Client: web` |
| POST | `/api/v1/analyze/slip` | multipart `file`, `expected_amount` (ไม่บังคับ) + header `X-TCS-Client: web` |
| POST | `/api/v1/analyze/social` | `{"url": "..."}` |
| POST | `/api/v1/analyze/email` | `{"email": "..."}` |
| POST | `/api/v1/analyze/sms` / `url` / `phone` | เหมือนเวอร์ชันแรก |
| POST | `/api/v1/reports` | `{"category": "item_trade", "phone": "...", "bank_account": "...", "facebook": "...", "email": "...", "consent": true}` |
| GET | `/api/health` | — |

## ตัวแปรแวดล้อม (Render)

| ตัวแปร | จำเป็น | ค่า |
|---|---|---|
| `TCS_ENGINE_SHA256` | ใช่ | จาก build log (ค้น `bin/tcs_engine`) |
| `TCS_HASH_PEPPER` | ใช่ (ใหม่) | ค่าสุ่ม ≥ 32 ตัว ห้ามเปลี่ยนภายหลัง |
| `TCS_DATABASE_URL` | แนะนำ (ใหม่) | Postgres จาก Neon (ฟรี) ต้องมี `sslmode=require` |
| `TCS_ALLOWED_ORIGINS`, `TCS_ALLOWED_HOSTS`, `TCS_TRUSTED_PROXIES` | ใช่ | เหมือนเดิม |

## ทดสอบ API ในเครื่อง

```bash
cd api && pip install -r requirements.txt && pytest -q    # ใช้ tests/fake_engine.py แทน Engine จริง
```
