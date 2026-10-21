# Thai Cyber Shield — กลไกความปลอดภัย (Security Measures)

เอกสารนี้อธิบายว่าแต่ละชั้นป้องกันอะไร ด้วยกลไกใด และมีข้อจำกัดอะไรบ้าง
หลักคิดของทั้งระบบคือ **Zero Trust**: ทุกชั้นไม่ไว้ใจข้อมูลที่ส่งมาจากชั้นอื่น แม้จะเป็นระบบของเราเอง

```
[ เบราว์เซอร์ ] --HTTPS/CORS--> [ FastAPI + Middleware ] --argv+stdin--> [ Ada/SPARK Engine ]
  textContent เท่านั้น              ตรวจซ้ำทุกอย่าง                         ตรวจ UTF-8 ระดับไบต์
  ตรวจผลตอบกลับซ้ำ                 ตรวจผลจาก Engine ซ้ำ                    ส่งออก JSON คำศัพท์ปิด
```

---

## 1. Secure Core Engine (Ada / SPARK)

| ภัยคุกคาม | กลไกป้องกัน | ไฟล์ |
|---|---|---|
| Buffer overflow / out-of-bounds | ทุกบัฟเฟอร์เป็น array ขนาดตายตัว ดัชนีเป็น constrained subtype (`CP_Index`, `Raw_Index`) เขียนเกินขอบเขต = ถูกพิสูจน์ว่าเป็นไปไม่ได้ด้วย GNATprove หรือเกิด `Constraint_Error` (ไม่มีการเขียนทับหน่วยความจำเงียบ ๆ) | `tcs_types.ads` |
| Memory leak / use-after-free | ไม่มี access type, ไม่มี `new`, ไม่ใช้ heap ในโค้ดวิเคราะห์ทั้งหมด (SPARK บังคับ) | ทุก `SPARK_Mode => On` |
| Integer overflow | `Risk_Score` เป็น range 0..100, การบวกคะแนนแบบ saturating (`Natural(Score)+W ≤ 200`) และคอมไพล์ด้วย `-gnato` | `tcs_types.adb` |
| Malformed / malicious UTF-8 | ตัวถอดรหัสแบบเข้มงวด: ปฏิเสธ overlong (`C0 AF`), surrogate, >U+10FFFF, ลำดับขาด, continuation byte หลงมา | `tcs_utf8.adb` |
| NUL-byte truncation, terminal escape injection | ปฏิเสธ C0 controls (ยกเว้น TAB/LF/CR), DEL, C1 controls ตั้งแต่ชั้นถอดรหัส | `tcs_utf8.adb` |
| Format string attack | Ada ไม่มี printf — ข้อมูลผู้ใช้ไม่เคยถูกตีความเป็น format; Engine **ไม่ echo input กลับ** ผลลัพธ์ประกอบจาก enum/ตัวเลขเท่านั้น รูปแบบ `%n %x` ถูกรายงานเป็น telemetry (`FORMAT_STRING`) | `tcs_output.adb`, `tcs_sms.adb` |
| JSON injection ในผลลัพธ์ | host ถูกส่งออกเฉพาะเมื่อผ่าน allow-list `[a-z0-9.:-]` เท่านั้น | `tcs_output.adb` |
| ReDoS / CPU exhaustion | ไม่ใช้ regex; ลูปทุกตัวมีขอบเขต `O(Len × KeywordLen)` และ Len ถูกจำกัด (SMS 1,000 / URL 2,048 / เบอร์ 32 code points) | `tcs_text.adb` |
| Input ใหญ่เกิน | อ่าน stdin เป็นก้อน 1 KB ไม่เกิน 8,192 ไบต์ เกิน = **ปฏิเสธ** (ไม่ตัดทิ้งเงียบ ๆ) | `tcs_main.adb` |
| Option / argument injection | argv มีได้ค่าเดียวจากเซตปิด `sms|url|phone`; ข้อมูลผู้ใช้มาทาง stdin เท่านั้น | `tcs_main.adb` |
| Crash | โค้ดวิเคราะห์เป็น SPARK (พิสูจน์ absence of runtime errors ได้) + `exception when others` ชั้นนอกสุด + `-fstack-check` ทำให้ stack ล้นกลายเป็น `Storage_Error` ที่จับได้ → ทุกกรณีจบด้วย JSON 1 บรรทัดและ exit code ที่กำหนด (0/2/3/64) | `tcs_main.adb`, `.gpr` |
| Binary hardening | PIE, Full RELRO (`-z relro -z now`), NX stack, stack protector | `tcs_engine.gpr` |

### ฟังก์ชันวิเคราะห์ 3 ตัว

1. **SMS Heuristic Parser** — จับคำไทย/อังกฤษ 11 หมวด (เร่งรีบ, ล่อเงิน, พนัน, สินเชื่อ, ลงทุน, อ้างหน่วยงาน, ธนาคาร, พัสดุ, ขอข้อมูล, ขอโอนเงิน, ช่องทางติดต่อ) บน *compact view* ที่ตัดช่องว่าง/จุด/ขีดออก และแปลงเลขไทย/ตัวอักษร fullwidth แล้ว จึงจับ “โ.อ.น เ-งิ-น” ได้ + ตรวจการแยกตัวอักษรเพื่อหลบ (`EVASION_SPACING`) + กฎผสม (อ้างหน่วยงาน+ลิงก์, เร่งรีบ+ลิงก์, ล่อ+ช่องทางติดต่อ) ซึ่งเป็นตัวทำนายที่แม่นที่สุด
2. **Deep URL Analyzer** — parser เขียนเองแบบ single-pass แยก scheme / userinfo / host / port / path และตรวจ: `javascript:`/`data:`, หลอกด้วย `@`, IP/IP แบบฐาน 10-16-8, Punycode, Unicode/homoglyph (ละติน+ซีริลลิก/กรีก), จุดแบบจีน `。`, TLD เสี่ยง, ลิงก์ย่อ, ชื่อแบรนด์ไทยที่ไม่ใช่โดเมนทางการ (จับคู่ suffix แบบเข้มงวด: `evilscb.co.th` ≠ `scb.co.th`), เว็บราชการปลอม, `.apk`, open redirect, `\` trick, จุดท้ายโดเมน
3. **Phone Pattern Matcher** — O(n) ไม่เกิน 32 ตัว: +693…+699 (รวม +697/+698) ซึ่งเป็นรหัสประเทศที่ไม่มีการจัดสรร, เบอร์ 69x ที่ไม่มี `+`, `+66 0…` (เลข 0 เกิน), ภูมิภาคเสี่ยง, เครือข่ายดาวเทียม +881/882/883, 1900, ความยาวไม่ตรงแผนเลขหมายไทย, ตัวเลขซ้ำผิดปกติ

> **ข้อจำกัดที่ต้องรู้:** การรับประกัน “100% ไม่มีช่องโหว่หน่วยความจำ/ไม่แครช” จะเป็นจริงเชิงคณิตศาสตร์ก็ต่อเมื่อรัน `gnatprove -P tcs_engine.gpr --level=2` ผ่านครบทุก check — ให้ถือผล proof เป็นเกณฑ์ปล่อยใช้งานใน CI ส่วน heuristic เป็นการประเมินความเสี่ยง ไม่ใช่การรับรองว่าปลอดภัย

---

## 2. Web API (Python / FastAPI)

| ภัยคุกคาม | กลไกป้องกัน | ไฟล์ |
|---|---|---|
| DDoS / flood | Token bucket ต่อ client (ค่าเริ่ม 30 req/นาที, burst 10) + global bucket; ตรวจ **ก่อน** อ่าน body | `ratelimit.py`, `security.py` |
| Brute-force ต่อเนื่อง | ระบบ strike: โดน 429 ครบ 20 ครั้งใน 60 วิ → แบน 15 นาที และเพิ่มเป็นสองเท่าทุกครั้ง (สูงสุด 24 ชม.) | `ratelimit.py` |
| ปลอม IP ผ่าน X-Forwarded-For | เชื่อ XFF เฉพาะเมื่อ peer อยู่ใน `TCS_TRUSTED_PROXIES` และอ่านจาก **ขวาไปซ้าย**; uvicorn รันด้วย `--no-proxy-headers` | `ratelimit.py` |
| หมุน IPv6 หลบ rate limit | รวม IPv6 เป็น /64 | `ratelimit.py` |
| Memory exhaustion จากการสุ่ม IP | LRU จำกัด 100,000 client | `ratelimit.py` |
| Body ใหญ่ / Slowloris | ตรวจ Content-Length + นับไบต์จริง (16 KB) + timeout ต่อ chunk 10 วิ; uvicorn จำกัด header/keep-alive/concurrency | `security.py`, Dockerfile |
| CSRF / simple-request bypass | POST ต้องเป็น `application/json` เท่านั้น (415), CORS ไม่ส่ง credentials, ไม่มี cookie | `security.py`, `main.py` |
| Host header attack | `TrustedHostMiddleware` | `main.py` |
| Mass assignment / type confusion | Pydantic `extra="forbid"`, `strict=True` (เลข 12345 ไม่ถูกแปลงเป็น string) | `models.py` |
| XSS | ไม่ HTML-escape input (จะทำลายหลักฐาน) แต่ **ไม่เคยตอบเป็น HTML**: JSON + `nosniff` + CSP `default-src 'none'; sandbox`; URL ที่มี `< > " \` { }` ถูกปฏิเสธ; ปิด handler 422 ค่าเริ่มของ FastAPI ที่ echo input กลับ | `sanitize.py`, `main.py` |
| SQL injection | ไม่มีฐานข้อมูล; ถ้าเพิ่มในอนาคต ใช้ parameterized query เท่านั้น — signature เป็นแค่ telemetry | `sanitize.py` |
| Command / shell injection | `create_subprocess_exec(*argv)` ไม่ผ่าน shell, mode จาก frozenset, ข้อมูลผ่าน stdin | `engine.py` |
| Engine ถูกสับเปลี่ยน | ตรวจ path แบบ absolute, resolve symlink, ไฟล์ปกติ, ห้าม group/world-writable, **pin SHA-256** (บังคับใน production) | `engine.py`, `config.py` |
| Engine ค้าง/โดนโจมตี | `prlimit` (CPU 2s, AS 128 MB, nofile 16, fsize 0, core 0), env ว่าง, cwd `/`, process group ของตัวเอง, timeout แล้ว `killpg SIGKILL`, อ่าน stdout ไม่เกิน 16 KB, semaphore จำกัด process พร้อมกัน, circuit breaker | `engine.py` |
| ผลลัพธ์ Engine ผิดรูป | JSON parse แบบเข้ม (ห้าม key ซ้ำ/NaN, ต้อง 1 บรรทัด) แล้ว validate ด้วย Pydantic คำศัพท์ปิด | `engine.py`, `models.py` |
| Log injection / ข้อมูลส่วนบุคคล (PDPA) | ไม่ log ข้อความดิบ ใช้ SHA-256 fingerprint; X-Request-ID รับเฉพาะ `[A-Za-z0-9-]{8,64}` | `sanitize.py` |
| Information disclosure | ปิด `/docs` และ OpenAPI ใน production, ลบ `Server`, error ไม่มี stack trace, health check ไม่บอกเวอร์ชัน | `main.py`, `security.py` |
| ตั้งค่าผิดแบบไม่ปลอดภัย | Fail-closed: CORS `*`, origin ไม่ใช่ https หรือไม่มี SHA-256 ใน production → ไม่ยอมเริ่มระบบ | `config.py` |

**Security headers:** HSTS (2 ปี + preload), CSP, X-Frame-Options DENY, nosniff, Referrer-Policy no-referrer, Permissions-Policy, COOP/CORP/COEP, Cache-Control no-store

> rate limiter เก็บสถานะในหน่วยความจำของ process — ถ้ารันหลาย worker/instance ให้ย้าย state ไป Redis โดยใช้อัลกอริทึมเดิม และวาง WAF/CDN (เช่น Cloudflare) ด้านหน้าสำหรับ DDoS ระดับเครือข่าย (L3/L4) ซึ่งแอปพลิเคชันป้องกันเองไม่ได้

---

## 3. Frontend (HTML / Tailwind / Vanilla JS)

| ภัยคุกคาม | กลไกป้องกัน |
|---|---|
| DOM-based / Reflected XSS | ไม่มี `innerHTML`/`eval`/`document.write` เลย ใช้ `createElement` + `textContent` เท่านั้น และ CSP `require-trusted-types-for 'script'; trusted-types 'none'` ทำให้เบราว์เซอร์**โยน error ทันที**ถ้ามีโค้ดใดพยายามเขียน HTML sink |
| ผลตอบกลับจาก API ถูกปลอม/ดัดแปลง | ตรวจ content-type, จำกัดขนาด 64 KB, `JSON.parse` ใน try, validate schema (score เป็นจำนวนเต็ม 0–100, level ในเซต, finding code ตาม regex); code ใช้เป็น key ของ `Map` เท่านั้น ไม่เคยแสดงข้อความจาก API ตรง ๆ |
| Script injection จากภายนอก | CSP `script-src 'self'` ไม่มี inline script, ไม่มี CDN JavaScript (Tailwind คอมไพล์ตอน build) |
| Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY` + frame-buster สำรองใน JS |
| Self-XSS ผ่าน Console | ข้อความเตือนภาษาไทยใน Console + ไม่มีข้อมูลลับใดอยู่ฝั่ง client (การ “บล็อก DevTools” ทำไม่ได้จริงและเลี่ยงได้เสมอ จึงไม่ใช้) |
| Prototype pollution | ใช้ `Map` แทน object lookup และ `Object.freeze(Object.prototype)` |
| สแปมปุ่ม | in-flight lock, cooldown 1.5 วิ, debounce การตรวจล่วงหน้า 250 ms |
| เน็ตล่ม/API ล่ม | AbortController timeout 10 วิ, retry สูงสุด 2 ครั้งแบบ exponential backoff + jitter เฉพาะ error ชั่วคราว, ข้อความ error ภาษาไทยพร้อมปุ่มลองใหม่, ตรวจสถานะ online/offline, ตัวจับ error สุดท้ายคลาย loading state เสมอ |
| ส่ง cookie/referrer รั่ว | `credentials: "omit"`, `referrerPolicy: "no-referrer"`, `redirect: "error"` |
| Open redirect ของปลายทาง API | `tcs-api-base` ถูกตัดเหลือเฉพาะ origin และต้องเป็น https |

---

## Checklist ก่อนขึ้น Production

1. `gnatprove -P engine/tcs_engine.gpr --level=2` ต้องผ่านทั้งหมด
2. ตั้ง `TCS_ENGINE_SHA256` ตามค่าที่ Docker build พิมพ์ออกมา
3. แก้โดเมน API ใน `frontend/public/index.html` (`tcs-api-base`) **และ** `connect-src` ใน `frontend/vercel.json` ให้ตรงกัน
4. ตั้ง `TCS_ALLOWED_ORIGINS` = โดเมน Vercel, `TCS_ALLOWED_HOSTS`, `TCS_TRUSTED_PROXIES`
5. รัน container ด้วย `--read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit`
6. ทบทวนรายชื่อโดเมนทางการใน `tcs_url.adb` (เป็น trust anchor) เป็นระยะ
7. ส่งเว็บเข้า HSTS preload list และทดสอบ header ด้วย securityheaders.com / Mozilla Observatory
