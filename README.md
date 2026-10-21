# Thai Cyber Shield

ระบบตรวจ SMS ลิงก์ และเบอร์โทรที่น่าสงสัยสำหรับคนไทย — 3 ชั้น:

| ส่วน | เทคโนโลยี | โฟลเดอร์ |
|---|---|---|
| Secure Core Engine | Ada 2012 / SPARK | `engine/` |
| Web API + Security Middleware | Python 3.12 / FastAPI | `api/` |
| Frontend | HTML / Tailwind CSS / Vanilla JS (Vercel) | `frontend/` |

รายละเอียดกลไกความปลอดภัยทั้งหมดอยู่ใน [SECURITY.md](SECURITY.md)

## 1. Engine

```bash
cd engine
gprbuild -P tcs_engine.gpr -XBUILD=release -p      # ต้องมี GNAT + gprbuild
gnatprove -P tcs_engine.gpr --level=2              # พิสูจน์ absence of runtime errors
./test_engine.sh
```

โปรโตคอล: `printf '%s' "<ข้อความ>" | bin/tcs_engine sms|url|phone` → JSON หนึ่งบรรทัด
exit code: 0 วิเคราะห์สำเร็จ, 2 ปฏิเสธ input, 3 ข้อผิดพลาดภายใน, 64 ใช้งานผิด

## 2. API

```bash
cd api
pip install -r requirements.txt
TCS_ENV=development TCS_ENGINE_PATH=$PWD/../engine/bin/tcs_engine \
TCS_ALLOWED_ORIGINS=http://localhost:3000 \
uvicorn app.main:app --port 8000 --no-server-header --no-proxy-headers
pytest -q        # ใช้ tests/fake_engine.py แทน Ada engine ได้
```

Endpoints: `POST /api/v1/analyze/sms` `{"message": "..."}`, `POST /api/v1/analyze/url` `{"url": "..."}`,
`POST /api/v1/analyze/phone` `{"phone": "..."}`, `GET /api/health`

Production: ใช้ `Dockerfile` ที่ root (build engine + runtime แบบ non-root)

## 3. Frontend (Vercel)

1. แก้ `<meta name="tcs-api-base">` ใน `public/index.html` และ `connect-src` ใน `vercel.json` เป็นโดเมน API จริง
2. Import โฟลเดอร์ `frontend/` เข้า Vercel (Root Directory = `frontend`) — `vercel.json` ตั้ง build (`npm run build` คอมไพล์ Tailwind) และ security headers ให้แล้ว
3. ทดสอบในเครื่อง: `npm install && npm run build && npx serve public`
