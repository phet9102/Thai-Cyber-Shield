/*!
 * Thai Cyber Shield - frontend controller (v2)
 *
 * Security model (full write-up in SECURITY.md):
 *  - NO HTML sinks anywhere: no innerHTML / outerHTML / insertAdjacentHTML /
 *    document.write / eval / new Function / string timers. Every byte that
 *    came from the API (including OCR text read from the user's image) is
 *    rendered with createElement + textContent. The CSP header
 *    `require-trusted-types-for 'script'; trusted-types 'none'` makes the
 *    browser itself throw if code ever tries an HTML sink -> DOM-XSS blocked
 *    by policy, not just by discipline.
 *  - API responses are untrusted: size cap, content-type check, JSON.parse
 *    in try/catch, closed-schema validation before anything is rendered.
 *    Finding codes / bank tokens are only ever Map keys.
 *  - Uploads: type allow-list + magic-byte sniffing + 5 MB cap BEFORE
 *    upload; previews use blob: URLs (revoked), never data from the server.
 *  - Anti-spam: in-flight lock, cooldown, debounced pre-validation,
 *    AbortController timeouts, bounded jittered retries.
 *  - Cold start: the free API host sleeps; the page wakes it on load and
 *    waits patiently instead of failing.
 *  - Clickjacking: frame-ancestors 'none' + X-Frame-Options (headers) plus
 *    a frame-buster fallback. Nothing secret lives in the client.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* 0. Clickjacking fallback + self-XSS warning                        */
  /* ------------------------------------------------------------------ */
  if (window.top !== window.self) {
    try { window.top.location.replace(window.self.location.href); } catch (_) { /* sandboxed */ }
    document.documentElement.replaceChildren();
    return;
  }
  try {
    console.log("%cหยุดก่อน!", "color:#FF5D73;font-size:32px;font-weight:700");
    console.log("%cหากมีคนบอกให้คัดลอกโค้ดมาวางที่นี่ นั่นคือกลโกงเพื่อขโมยบัญชีของคุณ อย่าวางโค้ดใด ๆ ที่ไม่ได้เขียนเอง", "font-size:15px");
  } catch (_) { /* console unavailable */ }

  /* ------------------------------------------------------------------ */
  /* 1. Configuration                                                    */
  /* ------------------------------------------------------------------ */
  function resolveApiBase() {
    var meta = document.querySelector('meta[name="tcs-api-base"]');
    var raw = meta ? meta.getAttribute("content") : "";
    try {
      var u = new URL(raw, window.location.origin);
      var local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
      if (u.protocol !== "https:" && !(local && u.protocol === "http:")) return null;
      if (u.username || u.password || u.search || u.hash) return null;
      return u.origin;
    } catch (_) {
      return null;
    }
  }

  var CONFIG = Object.freeze({
    apiBase: resolveApiBase(),
    textTimeoutMs: 20000,
    uploadTimeoutMs: 75000,
    warmTimeoutMs: 80000,
    maxRetries: 2,
    cooldownMs: 1500,
    debounceMs: 250,
    maxResponseChars: 131072,
    maxUploadBytes: 5 * 1024 * 1024
  });

  var MODES = Object.freeze({
    trade: Object.freeze({
      path: "/api/v1/analyze/trade", imagePath: "/api/v1/analyze/chat-image",
      field: "chat", max: 4000, multiline: true, text: true, upload: "optional",
      label: "ข้อความแชท",
      hint: "คัดลอกบทสนทนาซื้อขายมาวาง หรืออัปโหลดภาพหน้าจอแชท (ถ้าใส่ทั้งสองอย่าง ระบบจะอ่านจากรูป)",
      uploadLabel: "ภาพหน้าจอแชท (ไม่บังคับ)",
      placeholder: "เช่น ขายไอดี ROV โอนก่อนนะครับ ไม่รับกลาง มีคนรออยู่…",
      sample: "ขายไอดี ROV สกินเยอะ ราคาถูกกว่าตลาด โอนก่อนนะครับ ไม่รับกลาง ถ้าจะใช้กลางต้องเป็นแอดมินกลางของผม ทักไลน์ได้ มีคนรออยู่ รีบโอนภายใน 10 นาที บัญชีแม่ผม 123-4-56789-0"
    }),
    slip: Object.freeze({
      imagePath: "/api/v1/analyze/slip", text: false, upload: "required",
      uploadLabel: "ภาพสลิปโอนเงิน หรือ TrueMoney"
    }),
    link: Object.freeze({
      field: "url", max: 2048, multiline: false, text: true, upload: "none",
      label: "ลิงก์ Facebook ลิงก์เว็บ หรืออีเมล",
      hint: "วางลิงก์โปรไฟล์/โพสต์ Facebook ลิงก์เว็บไซต์ หรืออีเมลของอีกฝ่าย ไม่ต้องเปิดลิงก์ก่อนตรวจ",
      placeholder: "เช่น https://www.facebook.com/profile.php?id=…",
      sample: "https://facebook-copyright-appeal.help/checkpoint/verify"
    }),
    phone: Object.freeze({
      path: "/api/v1/analyze/phone", field: "phone", max: 32, multiline: false, text: true, upload: "none",
      label: "เบอร์ที่โทรหรือส่งข้อความมา",
      hint: "พิมพ์ตามที่เห็นบนหน้าจอ รวมเครื่องหมาย + ถ้ามี",
      placeholder: "เช่น +697 123 456 789",
      sample: "+697 2 345 6789"
    }),
    sms: Object.freeze({
      path: "/api/v1/analyze/sms", field: "message", max: 1000, multiline: true, text: true, upload: "none",
      label: "ข้อความ SMS ที่ได้รับ",
      hint: "คัดลอกข้อความทั้งหมดมาวาง รวมลิงก์และเบอร์โทรในข้อความด้วย",
      placeholder: "เช่น บัญชีของท่านถูกระงับ กรุณายืนยันตัวตนที่ลิงก์…",
      sample: "แจ้งเตือนด่วน! บัญชี KBank ของท่านถูกระงับ กรุณายืนยันตัวตนที่ https://bit.ly/kbank-verify ภายในวันนี้"
    })
  });

  var LEVELS = new Map([
    ["SAFE", { label: "ไม่พบสัญญาณอันตราย", summary: "ยังไม่พบรูปแบบที่ตรงกับมิจฉาชีพ แต่ควรระวังเสมอ" }],
    ["LOW", { label: "เสี่ยงต่ำ", summary: "มีจุดที่ควรสังเกต ตรวจสอบกับช่องทางทางการก่อน" }],
    ["MEDIUM", { label: "น่าสงสัย", summary: "พบหลายสัญญาณที่มิจฉาชีพมักใช้ อย่าเพิ่งโอนเงินหรือส่งของ" }],
    ["HIGH", { label: "เสี่ยงสูง", summary: "รูปแบบตรงกับการหลอกลวงที่พบบ่อย ไม่ควรทำตาม" }],
    ["CRITICAL", { label: "อันตรายมาก", summary: "เกือบแน่นอนว่าเป็นมิจฉาชีพ อย่าโอน อย่าส่งของ อย่าโทรกลับ" }]
  ]);

  var ADVICE = new Map([
    ["SAFE", ["ถ้ามีการขอข้อมูลส่วนตัวหรือให้โอนเงิน ให้ติดต่อหน่วยงานนั้นผ่านช่องทางทางการเอง"]],
    ["LOW", ["ตรวจสอบกับช่องทางทางการ ไม่ใช่เบอร์หรือลิงก์ที่อีกฝ่ายให้มา", "อย่าบอกรหัส OTP หรือรหัสผ่านกับใคร"]],
    ["MEDIUM", ["อย่าโอนเงินก่อน และอย่าส่งของจนกว่าจะเห็นเงินเข้าในแอปธนาคารของคุณเอง", "บล็อกและรายงานบัญชีผู้ติดต่อ"]],
    ["HIGH", ["หยุดการซื้อขายหรือการคุยทันที ไม่ต้องตอบกลับ", "ถ้าโอนไปแล้วหรือให้รหัสไปแล้ว ให้โทรหาธนาคารและสายด่วน 1441 ทันที", "ช่วยผู้อื่นด้วยการกดแจ้งเบาะแสด้านล่าง"]],
    ["CRITICAL", ["อย่าโอน อย่าส่งของ อย่าโทรกลับ ไม่ว่าอีกฝ่ายจะอ้างเป็นใคร", "ถ้าโอนเงินไปแล้ว โทร 1441 หรือธนาคารของคุณทันทีเพื่อขออายัดบัญชีปลายทาง", "ช่วยผู้อื่นด้วยการกดแจ้งเบาะแสด้านล่าง"]]
  ]);

  var MODE_ADVICE = new Map([
    ["slip", "สลิปพิสูจน์ไม่ได้ว่าเงินเข้าจริง ให้เปิดแอปธนาคารของคุณเองเพื่อดูยอดเข้าก่อนส่งของทุกครั้ง"],
    ["trade", "ใช้คนกลางที่คุณเลือกเองจากกลุ่มที่มีชื่อเสียง ไม่ใช่คนกลางที่อีกฝ่ายแนะนำ"]
  ]);

  // Finding code -> [Thai explanation, severity]. Lookup only.
  var FINDINGS = new Map([
    ["INVISIBLE_CHARS", ["มีตัวอักษรล่องหนซ่อนอยู่ ใช้หลบระบบกรองข้อความ", "high"]],
    ["BIDI_OVERRIDE", ["มีอักขระกลับทิศทางข้อความ ใช้พรางให้ดูเหมือนของจริง", "high"]],
    ["PAYLOAD_PATTERN", ["มีรูปแบบโค้ดหรือคำสั่งโจมตีแฝงอยู่", "mid"]],
    ["FORMAT_STRING", ["มีรูปแบบอักขระที่ใช้โจมตีระบบ (format string)", "mid"]],
    ["EVASION_SPACING", ["แยกตัวอักษรด้วยช่องว่างหรือจุด เพื่อหลบการตรวจจับคำ", "high"]],
    ["SMS_URGENCY", ["เร่งให้รีบทำ เช่น ด่วน ถูกระงับ ภายในวันนี้", "mid"]],
    ["SMS_MONEY_LURE", ["ล่อด้วยเงิน รางวัล หรือเครดิตฟรี", "mid"]],
    ["SMS_GAMBLING", ["โฆษณาพนันออนไลน์", "high"]],
    ["SMS_LOAN", ["เสนอสินเชื่ออนุมัติง่าย ไม่ต้องค้ำ", "mid"]],
    ["SMS_INVESTMENT", ["ชวนลงทุนผลตอบแทนสูง", "mid"]],
    ["SMS_AUTHORITY", ["อ้างชื่อหน่วยงานรัฐหรือเจ้าหน้าที่", "mid"]],
    ["SMS_BANK_BRAND", ["อ้างชื่อธนาคาร", "mid"]],
    ["SMS_PARCEL", ["อ้างเรื่องพัสดุหรือการจัดส่ง", "mid"]],
    ["SMS_CREDENTIAL_REQUEST", ["ขอให้ยืนยันตัวตน กรอกข้อมูล หรือรหัส OTP", "high"]],
    ["SMS_TRANSFER_REQUEST", ["ขอให้โอนเงินหรือชำระค่าธรรมเนียม", "high"]],
    ["SMS_CONTACT_CHANNEL", ["ให้แอด LINE โทรกลับ หรือกดลิงก์", "mid"]],
    ["SMS_CONTAINS_URL", ["มีลิงก์ในข้อความ", "mid"]],
    ["SMS_CONTAINS_SHORTENER", ["ใช้ลิงก์ย่อที่ซ่อนปลายทางจริง", "high"]],
    ["SMS_CONTAINS_APK", ["ชวนติดตั้งแอปนอก Store (.apk) ซึ่งอาจควบคุมเครื่องคุณได้", "high"]],
    ["SMS_CONTAINS_PHONE", ["มีเบอร์โทรในข้อความ", "info"]],
    ["SMS_MIXED_SCRIPT", ["ใช้ตัวอักษรต่างภาษาที่หน้าตาเหมือนกันมาปะปน", "high"]],
    ["COMBO_AUTHORITY_LINK", ["อ้างชื่อหน่วยงานหรือธนาคารพร้อมแนบลิงก์ เป็นรูปแบบหลอกลวงที่พบบ่อยที่สุด", "high"]],
    ["COMBO_URGENCY_LINK", ["เร่งให้รีบ พร้อมให้กดลิงก์หรือติดต่อกลับ", "high"]],
    ["COMBO_LURE_CONTACT", ["ล่อด้วยผลประโยชน์ แล้วให้ติดต่อช่องทางส่วนตัว", "high"]],
    ["URL_DANGEROUS_SCHEME", ["ลิงก์ชนิดที่สั่งรันโค้ดหรือเปิดไฟล์ในเครื่องได้", "high"]],
    ["URL_NO_TLS", ["ไม่ใช้การเชื่อมต่อแบบเข้ารหัส (https)", "mid"]],
    ["URL_USERINFO", ["มีเครื่องหมาย @ หลอกให้เห็นชื่อเว็บจริงด้านหน้า แต่ปลายทางเป็นเว็บอื่น", "high"]],
    ["URL_IP_HOST", ["ใช้เลข IP แทนชื่อเว็บไซต์", "high"]],
    ["URL_OBFUSCATED_IP", ["ซ่อนเลข IP ในรูปแบบแปลก ๆ เพื่อหลบการตรวจ", "high"]],
    ["URL_NONSTD_PORT", ["ใช้พอร์ตที่ไม่ใช่มาตรฐานของเว็บทั่วไป", "mid"]],
    ["URL_PUNYCODE", ["ชื่อเว็บเข้ารหัสแบบ Punycode อาจเป็นตัวอักษรหน้าตาเหมือนเว็บจริง", "high"]],
    ["URL_UNICODE_HOST", ["ชื่อเว็บมีตัวอักษรพิเศษที่ไม่ใช่ภาษาอังกฤษปกติ", "high"]],
    ["URL_HOMOGLYPH", ["ชื่อเว็บผสมตัวอักษรต่างภาษาที่หน้าตาเหมือนกัน (เว็บปลอม)", "high"]],
    ["URL_DEEP_SUBDOMAIN", ["ชื่อเว็บซ้อนหลายชั้นผิดปกติ", "mid"]],
    ["URL_MANY_HYPHENS", ["ชื่อเว็บมีขีดกลางหลายตัว มักใช้เลียนแบบชื่อแบรนด์", "mid"]],
    ["URL_SUSPICIOUS_TLD", ["ใช้นามสกุลโดเมนราคาถูกที่มิจฉาชีพนิยม", "mid"]],
    ["URL_SHORTENER", ["เป็นลิงก์ย่อ ไม่เห็นปลายทางจริง", "mid"]],
    ["URL_BRAND_IMPERSONATION", ["มีชื่อธนาคารหรือแบรนด์ดัง แต่ไม่ใช่โดเมนทางการ", "high"]],
    ["URL_GOV_LOOKALIKE", ["ทำทีเป็นเว็บราชการ (go.th) แต่ไม่ใช่", "high"]],
    ["URL_APK", ["ลิงก์ดาวน์โหลดแอป .apk นอก Store", "high"]],
    ["URL_PHISH_PATH", ["หน้าเว็บเกี่ยวกับการล็อกอินหรือยืนยันบัญชี", "mid"]],
    ["URL_ENCODED_EVASION", ["มีการเข้ารหัสหรือแทรกช่องว่างในลิงก์เพื่อหลบการตรวจ", "mid"]],
    ["URL_OPEN_REDIRECT", ["ลิงก์ส่งต่อไปยังเว็บอื่นอีกทอด", "mid"]],
    ["URL_EXCESSIVE_LENGTH", ["ลิงก์ยาวผิดปกติ", "info"]],
    ["URL_MALFORMED", ["รูปแบบลิงก์ผิดปกติ", "mid"]],
    ["URL_BACKSLASH_TRICK", ["ใช้เครื่องหมาย \\ หลอกเบราว์เซอร์ให้ไปเว็บอื่น", "high"]],
    ["URL_TRAILING_DOT", ["ชื่อเว็บลงท้ายด้วยจุด ใช้หลบรายชื่อเว็บที่บล็อกไว้", "mid"]],
    ["URL_OFFICIAL_DOMAIN", ["เป็นโดเมนทางการที่ระบบรู้จัก", "info"]],
    ["PH_UNASSIGNED_CC", ["รหัสประเทศ +693 ถึง +699 ไม่มีอยู่จริง เป็นเบอร์ปลอมของแก๊งคอลเซ็นเตอร์", "high"]],
    ["PH_SPOOF_NO_PLUS", ["เบอร์ขึ้นต้น 69x ซึ่งเป็นการปลอมเบอร์ต่างประเทศ", "high"]],
    ["PH_HIGH_RISK_REGION", ["มาจากประเทศที่มีรายงานแก๊งหลอกลวงคนไทยจำนวนมาก", "mid"]],
    ["PH_SATELLITE", ["เป็นเบอร์เครือข่ายดาวเทียมหรือเครือข่ายระหว่างประเทศ", "high"]],
    ["PH_INTERNATIONAL", ["เป็นเบอร์ต่างประเทศ", "mid"]],
    ["PH_PREMIUM_RATE", ["เป็นเบอร์ 1900 คิดค่าโทรแพง", "mid"]],
    ["PH_MALFORMED_TRUNK", ["มีเลข 0 เกินหลัง +66 ซึ่งเบอร์จริงจะไม่แสดงแบบนี้", "high"]],
    ["PH_INVALID_LENGTH", ["จำนวนหลักไม่ตรงกับเบอร์ที่ใช้ได้จริง", "mid"]],
    ["PH_ABNORMAL_PATTERN", ["ตัวเลขซ้ำกันผิดปกติ", "mid"]],
    ["PH_SERVICE_SHORTCODE", ["เป็นเบอร์สั้นของหน่วยงาน แต่เบอร์สั้นก็ถูกปลอมแสดงผลได้", "info"]],
    ["PH_THAI_MOBILE", ["รูปแบบเบอร์มือถือไทยถูกต้อง", "info"]],
    ["PH_THAI_LANDLINE", ["รูปแบบเบอร์บ้านไทยถูกต้อง", "info"]],
    ["PH_INVALID_FORMAT", ["มีตัวอักษรหรือสัญลักษณ์ที่ไม่ใช่เบอร์โทร", "high"]],
    ["TR_PAY_FIRST", ["ให้โอนเงินก่อนส่งของ", "mid"]],
    ["TR_REFUSE_ESCROW", ["ปฏิเสธการใช้คนกลาง", "high"]],
    ["TR_FAKE_ESCROW", ["ให้ใช้ “คนกลางของตัวเอง” หรือเว็บกลางที่อีกฝ่ายเลือก ซึ่งมักเป็นพวกเดียวกัน", "high"]],
    ["TR_URGENCY", ["เร่งให้รีบตัดสินใจ เช่น มีคนรอ เหลือชิ้นสุดท้าย", "mid"]],
    ["TR_TOO_GOOD", ["ราคาถูกผิดปกติหรือดีเกินจริง", "mid"]],
    ["TR_CREDENTIAL_REQUEST", ["ขอรหัสผ่าน รหัส OTP หรือให้เปลี่ยนอีเมลผูกบัญชี", "high"]],
    ["TR_OFF_PLATFORM", ["ชวนย้ายไปคุยนอกแพลตฟอร์ม เช่น LINE หรือ Telegram", "mid"]],
    ["TR_THIRD_PARTY_ACCOUNT", ["ให้โอนเข้าบัญชีคนอื่นที่ไม่ใช่ชื่อผู้ขาย", "high"]],
    ["TR_OVERPAY_REFUND", ["อ้างว่าโอนเกินแล้วขอให้โอนคืน (กลโกงพบบ่อย)", "high"]],
    ["TR_FEE_TRAP", ["เรียกค่าธรรมเนียม ค่าปลดล็อก หรือค่าประกันเพิ่ม", "high"]],
    ["TR_ANGPAO_PAYMENT", ["ให้จ่ายผ่านซองอั่งเปา TrueMoney ซึ่งติดตามเงินคืนได้ยาก", "mid"]],
    ["TR_SLIP_EXCUSE", ["อ้างว่าโอนแล้วแต่เงินไม่เข้า มักใช้คู่กับสลิปปลอม", "mid"]],
    ["TR_PRESSURE_THREAT", ["ข่มขู่ เช่น จะแจ้งความหรือประจาน", "mid"]],
    ["TR_GAME_CONTEXT", ["เป็นการซื้อขายไอเทมหรือไอดีเกม", "info"]],
    ["TR_CONTAINS_ACCOUNT_NO", ["มีเลขบัญชีหรือเบอร์โทรในแชท", "info"]],
    ["COMBO_PAY_FIRST_NO_ESCROW", ["ให้โอนก่อนและไม่ยอมใช้คนกลาง เป็นรูปแบบโกงที่พบบ่อยที่สุด", "high"]],
    ["COMBO_ESCROW_LINK", ["อ้างคนกลางพร้อมส่งลิงก์หรือให้ทักช่องทางอื่น", "high"]],
    ["COMBO_TAKEOVER_URGENCY", ["ขอรหัสบัญชีพร้อมเร่งหรือข่มขู่ (พยายามยึดบัญชี)", "high"]],
    ["SL_QR_VALID", ["QR ในสลิปถูกต้องตามรูปแบบ (ยืนยันได้แค่รูปแบบ ไม่ใช่ยอดเงินเข้า)", "info"]],
    ["SL_NO_QR", ["ไม่พบ QR ตรวจสอบสลิป ซึ่งสลิปธนาคารจริงส่วนใหญ่มี", "mid"]],
    ["SL_QR_MALFORMED", ["QR ในสลิปมีโครงสร้างผิดรูปแบบ", "high"]],
    ["SL_QR_CRC_INVALID", ["ค่าตรวจสอบ (CRC) ของ QR ไม่ถูกต้อง อาจเป็น QR ที่ถูกแก้ไข", "high"]],
    ["SL_QR_BANK_MISMATCH", ["ธนาคารใน QR ไม่ตรงกับธนาคารบนสลิป", "high"]],
    ["SL_REF_MISMATCH", ["เลขที่รายการบนสลิปไม่ตรงกับใน QR", "high"]],
    ["SL_REF_FORMAT", ["เลขที่รายการมีรูปแบบผิดปกติ", "mid"]],
    ["SL_BANK_UNKNOWN", ["ระบุธนาคารจากสลิปไม่ได้", "info"]],
    ["SL_AMOUNT_MISSING", ["อ่านยอดเงินจากสลิปไม่ได้", "mid"]],
    ["SL_AMOUNT_INVALID", ["ยอดเงินในสลิปผิดรูปแบบ", "mid"]],
    ["SL_AMOUNT_MISMATCH", ["ยอดเงินในสลิปไม่ตรงกับยอดที่ตกลงกัน", "high"]],
    ["SL_TIME_MISSING", ["อ่านวันเวลาจากสลิปไม่ได้", "mid"]],
    ["SL_TIME_INVALID", ["วันเวลาในสลิปเป็นไปไม่ได้ (เช่น วันที่ไม่มีจริง)", "high"]],
    ["SL_FUTURE_TIME", ["วันเวลาในสลิปเป็นอนาคต", "high"]],
    ["SL_OLD_SLIP", ["สลิปเก่าเกิน 3 วัน อาจเป็นสลิปเก่าที่นำมาใช้ซ้ำ", "mid"]],
    ["SL_EDITED_SOFTWARE", ["พบร่องรอยโปรแกรมแต่งภาพในไฟล์", "high"]],
    ["SL_TEXT_INCONSISTENT", ["ขนาดหรือความคมของตัวเลขยอดเงินไม่สอดคล้องกับส่วนอื่น", "mid"]],
    ["SL_DUPLICATE", ["เลขที่รายการนี้เคยถูกส่งมาตรวจโดยผู้ใช้อื่นแล้ว (สลิปใช้ซ้ำ)", "high"]],
    ["SL_LOW_OCR", ["ภาพไม่ชัด ระบบอ่านข้อความได้ไม่ครบ", "info"]],
    ["SL_TRUEMONEY", ["เป็นสลิป TrueMoney Wallet", "info"]],
    ["SL_BAD_INPUT", ["อ่านข้อมูลสลิปไม่ได้", "mid"]],
    ["SO_FACEBOOK_OFFICIAL", ["เป็นลิงก์ Facebook จริง", "info"]],
    ["SO_PROFILE_NUMERIC", ["เป็นโปรไฟล์แบบเลข ID (ไม่ได้ตั้งชื่อผู้ใช้)", "info"]],
    ["SO_NEW_ACCOUNT_ID", ["เลข ID อยู่ในช่วงของบัญชีที่สร้างไม่นาน (สัญญาณอ่อน)", "mid"]],
    ["SO_SHARE_LINK", ["เป็นลิงก์แชร์ที่ซ่อนปลายทางจริง", "info"]],
    ["SO_LINK_SHIM", ["ลิงก์ส่งต่อออกจาก Facebook ไปเว็บอื่น", "mid"]],
    ["SO_MARKETPLACE", ["เป็นสินค้าใน Marketplace", "info"]],
    ["SO_FB_LOOKALIKE", ["ไม่ใช่ Facebook แต่ตั้งชื่อเว็บให้เหมือน Facebook/Meta", "high"]],
    ["SO_PHISH_PATH", ["หน้าเว็บอ้างเรื่องเพจละเมิด ยืนยันบัญชี หรือกู้บัญชี", "high"]],
    ["EM_INVALID", ["รูปแบบอีเมลไม่ถูกต้อง", "mid"]],
    ["EM_FREE_PROVIDER", ["เป็นอีเมลฟรี (หน่วยงานจริงไม่ใช้)", "info"]],
    ["EM_DISPOSABLE", ["เป็นอีเมลชั่วคราวแบบใช้แล้วทิ้ง", "high"]],
    ["EM_BRAND_IN_FREE", ["ใช้ชื่อธนาคารหรือหน่วยงานบนอีเมลฟรี", "high"]],
    ["EM_DIGIT_HEAVY", ["ชื่ออีเมลมีตัวเลขยาวผิดปกติ", "info"]],
    ["EM_UNICODE", ["อีเมลมีตัวอักษรพิเศษที่อาจปลอมให้เหมือนของจริง", "high"]],
    ["REPORTED_MANY", ["มีผู้ใช้หลายคนแจ้งเบาะแสข้อมูลนี้", "high"]],
    ["REPORTED_MULTIPLE", ["มีผู้ใช้ 2 คนแจ้งเบาะแสข้อมูลนี้", "high"]],
    ["REPORTED_ONCE", ["มีผู้ใช้ 1 คนแจ้งเบาะแส (ยังไม่ยืนยัน)", "mid"]],
    ["LINKED_TO_REPORTED", ["เชื่อมโยงกับข้อมูลที่อยู่ในรายงานโกงอื่น", "high"]]
  ]);

  var BANK_NAMES = new Map([
    ["KBANK", "กสิกรไทย"], ["SCB", "ไทยพาณิชย์"], ["KTB", "กรุงไทย"], ["BBL", "กรุงเทพ"],
    ["BAY", "กรุงศรีอยุธยา"], ["TTB", "ทหารไทยธนชาต"], ["GSB", "ออมสิน"], ["BAAC", "ธ.ก.ส."],
    ["GHB", "อาคารสงเคราะห์"], ["KKP", "เกียรตินาคินภัทร"], ["CIMB", "ซีไอเอ็มบีไทย"],
    ["UOB", "ยูโอบี"], ["TISCO", "ทิสโก้"], ["LHB", "แลนด์ แอนด์ เฮ้าส์"],
    ["TRUEMONEY", "TrueMoney Wallet"], ["UNKNOWN", "ระบุไม่ได้"]
  ]);

  var KIND_LABELS = new Map([
    ["phone", "เบอร์โทร"], ["bank_account", "เลขบัญชี"], ["email", "อีเมล"],
    ["facebook", "Facebook"], ["url", "ลิงก์"]
  ]);

  var ERROR_TEXT = new Map([
    ["RATE_LIMITED", "ตรวจถี่เกินไป รอสักครู่แล้วลองใหม่"],
    ["INVALID_INPUT", "รูปแบบข้อมูลไม่ถูกต้อง ตรวจสอบสิ่งที่วางแล้วลองใหม่"],
    ["INPUT_TOO_LONG", "ข้อความยาวเกินกำหนด"],
    ["INPUT_INVALID_UTF8", "ข้อความมีอักขระที่อ่านไม่ได้"],
    ["INPUT_FORBIDDEN_CONTROL", "ข้อความมีอักขระควบคุมที่ไม่อนุญาต"],
    ["PAYLOAD_TOO_LARGE", "ไฟล์หรือข้อมูลใหญ่เกินกำหนด"],
    ["UNSUPPORTED_MEDIA_TYPE", "รูปแบบการส่งข้อมูลไม่ถูกต้อง"],
    ["UNSUPPORTED_IMAGE_TYPE", "รองรับเฉพาะรูป PNG, JPG และ WebP"],
    ["IMAGE_TOO_LARGE", "รูปใหญ่เกินไป ใช้รูปไม่เกิน 5 MB"],
    ["IMAGE_CORRUPT", "ไฟล์รูปเสียหรือเปิดไม่ได้"],
    ["IMAGE_TYPE_MISMATCH", "นามสกุลไฟล์ไม่ตรงกับชนิดรูปจริง"],
    ["IMAGE_DIMENSIONS", "ขนาดรูปเล็กหรือใหญ่เกินไป"],
    ["EMPTY_FILE", "ไฟล์ว่างเปล่า"],
    ["NO_TEXT_FOUND", "อ่านข้อความจากรูปไม่ได้ ลองใช้ภาพที่คมชัดขึ้น"],
    ["INVALID_EXPECTED_AMOUNT", "ยอดเงินที่ใส่ต้องเป็นตัวเลข เช่น 1500 หรือ 1500.50"],
    ["SERVICE_UNAVAILABLE", "ระบบตรวจไม่ว่างชั่วคราว ลองใหม่อีกครั้งในไม่กี่วินาที"],
    ["TIMEOUT", "เชื่อมต่อนานเกินไป ตรวจสอบอินเทอร์เน็ตแล้วลองใหม่"],
    ["OFFLINE", "ไม่ได้เชื่อมต่ออินเทอร์เน็ต เชื่อมต่อแล้วลองใหม่"],
    ["NETWORK", "เชื่อมต่อระบบตรวจไม่ได้ ลองใหม่อีกครั้ง"],
    ["BAD_RESPONSE", "ได้รับผลตอบกลับที่ไม่ถูกต้อง ระบบปฏิเสธการแสดงผลเพื่อความปลอดภัย"],
    ["CONFIG", "ตั้งค่าที่อยู่ระบบตรวจไม่ถูกต้อง (ผู้ดูแลต้องแก้ tcs-api-base)"],
    ["REPORT_LIMIT_REACHED", "วันนี้คุณแจ้งเบาะแสครบจำนวนแล้ว ลองใหม่พรุ่งนี้"],
    ["ALREADY_REPORTED", "คุณเคยแจ้งข้อมูลนี้แล้ว"],
    ["NO_IDENTIFIER", "ใส่ข้อมูลอย่างน้อย 1 ช่อง"],
    ["INVALID_PHONE", "เบอร์โทรไม่ถูกต้อง"],
    ["INVALID_BANK_ACCOUNT", "เลขบัญชีต้องเป็นตัวเลข 10–15 หลัก"],
    ["INVALID_FACEBOOK", "ลิงก์ Facebook ไม่ถูกต้อง ใช้ลิงก์โปรไฟล์ เพจ หรือกลุ่ม"],
    ["INVALID_EMAIL", "อีเมลไม่ถูกต้อง"]
  ]);

  /* ------------------------------------------------------------------ */
  /* 2. Client-side pre-validation (UX only - the server re-validates)   */
  /* ------------------------------------------------------------------ */
  var CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;
  var URL_FORBIDDEN_RE = /[<>"`{}\\^|]/;
  var PHONE_RE = /^[+＋0-9๐-๙０-９ ()\-./]{3,32}$/;
  var EMAIL_RE = /^[^\s@\/<>"]{1,64}@[^\s@\/<>"]{1,253}\.[A-Za-z]{2,24}$/;
  var LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;
  var AMOUNT_RE = /^[0-9]{1,11}(\.[0-9]{1,2})?$/;
  var ALLOWED_TYPES = new Set(["image/png", "image/jpeg", "image/webp"]);

  function validateText(mode, value) {
    var cfg = MODES[mode];
    var v = value.trim();
    if (!v) return "กรุณาใส่สิ่งที่ต้องการตรวจ";
    if (v.length > cfg.max) return "ยาวเกิน " + cfg.max + " ตัวอักษร";
    if (LONE_SURROGATE_RE.test(v)) return "มีอักขระที่ไม่ถูกต้อง";
    if (CONTROL_RE.test(v.replace(/[\t\n\r]/g, ""))) return "มีอักขระควบคุมที่ไม่อนุญาต";
    if (mode === "link") {
      if (v.indexOf("@") !== -1 && v.indexOf("/") === -1) {
        if (!EMAIL_RE.test(v)) return "รูปแบบอีเมลไม่ถูกต้อง";
      } else if (URL_FORBIDDEN_RE.test(v)) {
        return "ลิงก์มีอักขระที่ใช้ในลิงก์ไม่ได้ เช่น < > \" `";
      }
    }
    if (mode === "phone") {
      if (!PHONE_RE.test(v)) return "ใส่ได้เฉพาะตัวเลข + ( ) - และช่องว่าง";
      if (v.replace(/[^0-9๐-๙０-９]/g, "").length < 3) return "ตัวเลขน้อยเกินไป";
    }
    return "";
  }

  function isFacebookHost(host) {
    var h = host.toLowerCase().replace(/\.$/, "");
    return ["facebook.com", "fb.com", "fb.me", "fb.watch", "messenger.com"].some(function (d) {
      return h === d || h.slice(-(d.length + 1)) === "." + d;
    });
  }

  // Decide which endpoint a "link" input goes to. Look-alike FB domains go
  // to the social analyser too (it scores them), so match loosely there.
  function routeLink(v) {
    if (v.indexOf("@") !== -1 && v.indexOf("/") === -1) {
      return { path: "/api/v1/analyze/email", field: "email", mode: "email" };
    }
    var host = "";
    try { host = new URL(/^[a-z][a-z0-9+.\-]*:\/\//i.test(v) ? v : "https://" + v).hostname; } catch (_) { host = ""; }
    if (host && (isFacebookHost(host) || /face|fb|meta/i.test(host))) {
      return { path: "/api/v1/analyze/social", field: "url", mode: "social" };
    }
    return { path: "/api/v1/analyze/url", field: "url", mode: "url" };
  }

  /* ------------------------------------------------------------------ */
  /* 3. Response validation (zero trust)                                 */
  /* ------------------------------------------------------------------ */
  var CODE_RE = /^[A-Z0-9_]{1,40}$/;
  var HOST_RE = /^[a-z0-9.:\-]{1,253}$/;
  var RESULT_MODES = new Set(["sms", "url", "phone", "trade", "slip", "social", "email"]);

  function isInt(n, lo, hi) { return typeof n === "number" && Number.isInteger(n) && n >= lo && n <= hi; }
  function isStr(s, max) { return typeof s === "string" && s.length <= max; }
  function optStr(s, max) { return s === null || s === undefined || isStr(s, max); }

  function isValidResult(o, expectedMode) {
    if (!o || typeof o !== "object" || Array.isArray(o)) return false;
    if (!RESULT_MODES.has(o.mode) || (expectedMode && o.mode !== expectedMode)) return false;
    if (!isInt(o.score, 0, 100)) return false;
    if (!LEVELS.has(o.level)) return false;
    if (!Array.isArray(o.findings) || o.findings.length > 40) return false;
    for (var i = 0; i < o.findings.length; i++) {
      if (typeof o.findings[i] !== "string" || !CODE_RE.test(o.findings[i])) return false;
    }
    if (o.host !== null && o.host !== undefined && (typeof o.host !== "string" || !HOST_RE.test(o.host))) return false;
    if (o.identifiers !== undefined) {
      if (!Array.isArray(o.identifiers) || o.identifiers.length > 40) return false;
      for (var j = 0; j < o.identifiers.length; j++) {
        var it = o.identifiers[j];
        if (!it || typeof it !== "object" || !KIND_LABELS.has(it.kind) || !isStr(it.display, 300) ||
            !isInt(it.reporters, 0, 1e7) || !isInt(it.reports, 0, 1e7) || !isInt(it.linked_reports, 0, 1e7)) return false;
      }
    }
    if (o.slip !== null && o.slip !== undefined) {
      var s = o.slip;
      if (typeof s !== "object" || !BANK_NAMES.has(s.bank) || !optStr(s.amount, 20) ||
          !optStr(s.time, 20) || !optStr(s.ref_tail, 8) || typeof s.qr_found !== "boolean" ||
          !(s.qr_valid === null || s.qr_valid === undefined || typeof s.qr_valid === "boolean")) return false;
    }
    if (!optStr(o.ocr_text, 3000)) return false;
    if (!(o.ocr_conf === null || o.ocr_conf === undefined || isInt(o.ocr_conf, 0, 100))) return false;
    return true;
  }

  function safeErrorCode(o) {
    if (o && typeof o === "object" && typeof o.error === "string" && CODE_RE.test(o.error)) return o.error;
    return "";
  }

  /* ------------------------------------------------------------------ */
  /* 4. Network layer                                                    */
  /* ------------------------------------------------------------------ */
  function ApiError(code, retryable) { this.code = code; this.retryable = !!retryable; }
  function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  async function requestOnce(method, path, body, headers, timeoutMs, outerSignal) {
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, timeoutMs);
    var onOuterAbort = function () { ctrl.abort(); };
    if (outerSignal) outerSignal.addEventListener("abort", onOuterAbort, { once: true });
    try {
      var res;
      try {
        res = await fetch(CONFIG.apiBase + path, {
          method: method,
          mode: "cors",
          credentials: "omit",
          cache: "no-store",
          redirect: "error",
          referrerPolicy: "no-referrer",
          headers: headers,
          body: body,
          signal: ctrl.signal
        });
      } catch (e) {
        if (outerSignal && outerSignal.aborted) throw new ApiError("ABORTED", false);
        if (ctrl.signal.aborted) throw new ApiError("TIMEOUT", true);
        throw new ApiError(navigator.onLine === false ? "OFFLINE" : "NETWORK", true);
      }
      var ctype = (res.headers.get("content-type") || "").toLowerCase();
      if (ctype.indexOf("application/json") !== 0) {
        throw new ApiError(res.status >= 500 ? "SERVICE_UNAVAILABLE" : "BAD_RESPONSE", res.status >= 500);
      }
      var text = await res.text();
      if (text.length > CONFIG.maxResponseChars) throw new ApiError("BAD_RESPONSE", false);
      var data;
      try { data = JSON.parse(text); } catch (_) { throw new ApiError("BAD_RESPONSE", false); }
      if (res.ok) return data;
      var code = safeErrorCode(data);
      if (res.status === 429) throw new ApiError(code === "REPORT_LIMIT_REACHED" ? code : "RATE_LIMITED", false);
      if (res.status >= 500) throw new ApiError("SERVICE_UNAVAILABLE", true);
      throw new ApiError(ERROR_TEXT.has(code) ? code : "INVALID_INPUT", false);
    } finally {
      clearTimeout(timer);
      if (outerSignal) outerSignal.removeEventListener("abort", onOuterAbort);
    }
  }

  async function withRetry(fn, maxRetries, signal) {
    var attempt = 0;
    for (;;) {
      try {
        return await fn();
      } catch (err) {
        var e = err instanceof ApiError ? err : new ApiError("NETWORK", true);
        if (!e.retryable || attempt >= maxRetries || (signal && signal.aborted)) throw e;
        attempt += 1;
        await sleep(Math.floor(Math.random() * 400 * Math.pow(2, attempt)));
      }
    }
  }

  function postJson(path, payload, signal) {
    return withRetry(function () {
      return requestOnce("POST", path, JSON.stringify(payload),
        { "Content-Type": "application/json" }, CONFIG.textTimeoutMs, signal);
    }, CONFIG.maxRetries, signal);
  }

  function postForm(path, form, signal) {
    // No Content-Type header: the browser sets the multipart boundary.
    // X-TCS-Client forces a CORS preflight (see ContentTypeMiddleware).
    return withRetry(function () {
      return requestOnce("POST", path, form, { "X-TCS-Client": "web" }, CONFIG.uploadTimeoutMs, signal);
    }, 1, signal);
  }

  /* ------------------------------------------------------------------ */
  /* 5. Cold-start wake-up                                               */
  /* ------------------------------------------------------------------ */
  var warm = { state: "idle", promise: null };

  function wakeApi() {
    if (!CONFIG.apiBase) return Promise.resolve(false);
    if (warm.promise) return warm.promise;
    warm.state = "pending";
    var slowTimer = setTimeout(function () {
      if (warm.state === "pending") setWarmStatus("กำลังเตรียมระบบตรวจ…");
    }, 1500);
    warm.promise = (async function () {
      var deadline = Date.now() + CONFIG.warmTimeoutMs;
      while (Date.now() < deadline) {
        try {
          await requestOnce("GET", "/api/health", undefined, {}, Math.min(30000, deadline - Date.now()), null);
          warm.state = "ok";
          clearTimeout(slowTimer);
          setWarmStatus("");
          return true;
        } catch (_) {
          await sleep(2500);
        }
      }
      warm.state = "fail";
      warm.promise = null;            // allow another attempt later
      clearTimeout(slowTimer);
      setWarmStatus("");
      return false;
    })();
    return warm.promise;
  }

  /* ------------------------------------------------------------------ */
  /* 6. DOM helpers - textContent only                                  */
  /* ------------------------------------------------------------------ */
  function $(id) { return document.getElementById(id); }
  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function show(node, visible) { node.classList.toggle("hidden", !visible); }

  var dom = {
    tabs: Array.prototype.slice.call(document.querySelectorAll('[role="tab"]')),
    form: $("checker-form"),
    textWrap: $("text-wrap"), label: $("field-label"), hint: $("field-hint"),
    count: $("field-count"), error: $("field-error"),
    uploadWrap: $("upload-wrap"), uploadLabel: $("upload-label"), dropzone: $("dropzone"),
    fileInput: $("file-input"), preview: $("preview"), previewImg: $("preview-img"),
    previewName: $("preview-name"), previewRemove: $("preview-remove"), uploadError: $("upload-error"),
    expectedWrap: $("expected-wrap"), expected: $("expected-input"),
    submit: $("submit-btn"), sample: $("sample-btn"), clear: $("clear-btn"),
    warmStatus: $("warm-status"),
    result: $("result"), arc: $("gauge-arc"), score: $("gauge-score"),
    level: $("result-level"), summary: $("result-summary"), host: $("result-host"),
    slipWrap: $("slip-wrap"), slipFacts: $("slip-facts"),
    reasonsWrap: $("reasons-wrap"), reasons: $("reasons"),
    idsWrap: $("ids-wrap"), ids: $("ids"),
    advice: $("advice"), adviceList: $("advice-list"),
    ocrWrap: $("ocr-wrap"), ocrText: $("ocr-text"), ocrConf: $("ocr-conf"),
    errorBox: $("error-box"), errorText: $("error-text"), retry: $("retry-btn"),
    repOpen: $("report-open"), repForm: $("report-form"), repCategory: $("rep-category"),
    repPhone: $("rep-phone"), repBank: $("rep-bank"), repFacebook: $("rep-facebook"),
    repEmail: $("rep-email"), repConsent: $("rep-consent"), repError: $("rep-error"),
    repDone: $("rep-done"), repSubmit: $("rep-submit"), repCancel: $("rep-cancel")
  };
  var field = $("field-text");
  var ARC_LEN = 326.73;

  function setWarmStatus(text) {
    dom.warmStatus.textContent = text;
    show(dom.warmStatus, !!text);
  }

  /* ------------------------------------------------------------------ */
  /* 7. State                                                            */
  /* ------------------------------------------------------------------ */
  var state = {
    mode: "trade",
    inFlight: false,
    lastSubmitAt: 0,
    controller: null,
    drafts: { trade: "", link: "", phone: "", sms: "" },
    file: null,
    previewUrl: null,
    lastInput: ""
  };

  /* ------------------------------------------------------------------ */
  /* 8. Rendering                                                        */
  /* ------------------------------------------------------------------ */
  function resetResult() {
    dom.result.setAttribute("data-level", "IDLE");
    dom.arc.setAttribute("stroke-dashoffset", String(ARC_LEN));
    dom.score.textContent = "—";
    dom.level.textContent = "ยังไม่ได้ตรวจ";
    dom.summary.textContent = "ผลจะแสดงที่นี่ พร้อมเหตุผลและสิ่งที่ควรทำต่อ";
    [dom.reasons, dom.adviceList, dom.ids, dom.slipFacts].forEach(function (n) { n.replaceChildren(); });
    dom.ocrText.textContent = "";
    [dom.host, dom.slipWrap, dom.reasonsWrap, dom.idsWrap, dom.advice, dom.ocrWrap, dom.errorBox]
      .forEach(function (n) { show(n, false); });
  }

  function reputationText(it) {
    if (it.reporters === 0 && it.linked_reports === 0) return { text: "ยังไม่มีผู้แจ้งเบาะแส", hot: false };
    var parts = [];
    if (it.reporters > 0) parts.push("มีผู้แจ้ง " + it.reporters + " คน");
    if (it.linked_reports > 0) parts.push("เชื่อมโยงกับรายงานอื่น " + it.linked_reports + " รายการ");
    return { text: parts.join(" · "), hot: it.reporters >= 2 || it.linked_reports > 0 };
  }

  function renderResult(data, uiMode) {
    var level = LEVELS.get(data.level);
    show(dom.errorBox, false);
    dom.result.setAttribute("data-level", data.level);
    dom.arc.setAttribute("stroke-dashoffset", String(ARC_LEN * (1 - data.score / 100)));
    dom.score.textContent = String(data.score);
    dom.level.textContent = level.label;
    dom.summary.textContent = level.summary;

    if (data.host) {
      dom.host.textContent = (data.mode === "email" ? "โดเมนของอีเมล: " : "ปลายทางจริงของลิงก์: ") + data.host;
      show(dom.host, true);
    } else {
      show(dom.host, false);
    }

    // Slip facts
    dom.slipFacts.replaceChildren();
    if (data.slip) {
      var s = data.slip;
      var rows = [
        ["ธนาคาร", BANK_NAMES.get(s.bank)],
        ["ยอดเงิน", s.amount ? Number(s.amount).toLocaleString("th-TH", { minimumFractionDigits: 2 }) + " บาท" : "อ่านไม่ได้"],
        ["วันเวลา", s.time || "อ่านไม่ได้"],
        ["เลขที่รายการ", s.ref_tail ? "ลงท้ายด้วย " + s.ref_tail : "อ่านไม่ได้"],
        ["QR ตรวจสอบ", !s.qr_found ? "ไม่พบ" : (s.qr_valid ? "พบ และรูปแบบถูกต้อง" : "พบ แต่รูปแบบไม่ถูกต้อง")]
      ];
      rows.forEach(function (r) {
        dom.slipFacts.appendChild(el("dt", null, r[0]));
        dom.slipFacts.appendChild(el("dd", null, r[1]));
      });
    }
    show(dom.slipWrap, !!data.slip);

    // Reasons
    var items = data.findings.map(function (code) {
      var f = FINDINGS.get(code) || ["พบความผิดปกติอื่น", "mid"];
      var li = el("li");
      li.appendChild(el("span", { "class": "reason-dot", "data-sev": f[1], "aria-hidden": "true" }));
      li.appendChild(el("span", null, f[0]));
      return li;
    });
    dom.reasons.replaceChildren.apply(dom.reasons, items);
    show(dom.reasonsWrap, items.length > 0);

    // Identifiers + reputation
    var idItems = (data.identifiers || []).map(function (it) {
      var rep = reputationText(it);
      var li = el("li");
      li.appendChild(el("span", { "class": "id-value" }, KIND_LABELS.get(it.kind) + " " + it.display));
      li.appendChild(el("span", { "class": "id-rep", "data-hot": rep.hot ? "true" : "false" }, rep.text));
      return li;
    });
    dom.ids.replaceChildren.apply(dom.ids, idItems);
    show(dom.idsWrap, idItems.length > 0);

    // Advice
    var advice = (ADVICE.get(data.level) || []).slice();
    if (MODE_ADVICE.has(uiMode) && (uiMode === "slip" || data.level !== "SAFE")) advice.unshift(MODE_ADVICE.get(uiMode));
    dom.adviceList.replaceChildren.apply(dom.adviceList, advice.map(function (t) { return el("li", null, t); }));
    show(dom.advice, advice.length > 0);

    // OCR text (the user's own image, still rendered as plain text)
    if (typeof data.ocr_text === "string" && data.ocr_text) {
      dom.ocrText.textContent = data.ocr_text;
      dom.ocrConf.textContent = typeof data.ocr_conf === "number" ? "(ความมั่นใจ " + data.ocr_conf + "%)" : "";
      show(dom.ocrWrap, true);
    } else {
      show(dom.ocrWrap, false);
    }

    dom.result.classList.remove("reveal");
    void dom.result.offsetWidth;
    dom.result.classList.add("reveal");
  }

  function renderError(code) {
    dom.errorText.textContent = ERROR_TEXT.get(code) || ERROR_TEXT.get("NETWORK");
    show(dom.errorBox, true);
    var noRetry = ["INVALID_INPUT", "CONFIG", "INPUT_TOO_LONG", "UNSUPPORTED_IMAGE_TYPE", "IMAGE_TOO_LARGE",
      "IMAGE_CORRUPT", "IMAGE_TYPE_MISMATCH", "IMAGE_DIMENSIONS", "EMPTY_FILE", "NO_TEXT_FOUND",
      "INVALID_EXPECTED_AMOUNT"];
    show(dom.retry, noRetry.indexOf(code) === -1);
  }

  function setLoading(on, label) {
    state.inFlight = on;
    dom.submit.disabled = on;
    dom.submit.classList.toggle("is-loading", on);
    dom.submit.querySelector(".btn-label").textContent = on ? (label || "กำลังตรวจ") : "ตรวจเลย";
    dom.result.setAttribute("aria-busy", on ? "true" : "false");
  }

  /* ------------------------------------------------------------------ */
  /* 9. File handling: allow-list, magic bytes, size, blob preview       */
  /* ------------------------------------------------------------------ */
  async function sniffImage(file) {
    var b = new Uint8Array(await file.slice(0, 12).arrayBuffer());
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) return "image/png";
    if (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return "image/jpeg";
    if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
        b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
    return "";
  }

  function clearFile() {
    if (state.previewUrl) URL.revokeObjectURL(state.previewUrl);
    state.previewUrl = null;
    state.file = null;
    dom.fileInput.value = "";
    dom.previewImg.removeAttribute("src");
    dom.previewName.textContent = "";
    dom.uploadError.textContent = "";
    show(dom.preview, false);
  }

  async function acceptFile(file) {
    clearFile();
    if (!file) return;
    if (file.size === 0) { dom.uploadError.textContent = ERROR_TEXT.get("EMPTY_FILE"); return; }
    if (file.size > CONFIG.maxUploadBytes) { dom.uploadError.textContent = ERROR_TEXT.get("IMAGE_TOO_LARGE"); return; }
    if (!ALLOWED_TYPES.has(file.type)) { dom.uploadError.textContent = ERROR_TEXT.get("UNSUPPORTED_IMAGE_TYPE"); return; }
    var real;
    try { real = await sniffImage(file); } catch (_) { real = ""; }
    if (!real) { dom.uploadError.textContent = ERROR_TEXT.get("IMAGE_TYPE_MISMATCH"); return; }
    state.file = file;
    state.previewUrl = URL.createObjectURL(file);
    dom.previewImg.setAttribute("src", state.previewUrl);
    dom.previewName.textContent = file.name.slice(0, 80);
    show(dom.preview, true);
  }

  dom.fileInput.addEventListener("change", function () {
    acceptFile(dom.fileInput.files && dom.fileInput.files[0]);
  });
  dom.previewRemove.addEventListener("click", clearFile);
  ["dragenter", "dragover"].forEach(function (t) {
    dom.dropzone.addEventListener(t, function (ev) { ev.preventDefault(); dom.dropzone.classList.add("is-over"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    dom.dropzone.addEventListener(t, function (ev) { ev.preventDefault(); dom.dropzone.classList.remove("is-over"); });
  });
  dom.dropzone.addEventListener("drop", function (ev) {
    var f = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
    if (f) acceptFile(f);
  });
  // Paste a screenshot straight from the clipboard (desktop)
  document.addEventListener("paste", function (ev) {
    if (MODES[state.mode].upload === "none") return;
    var items = ev.clipboardData && ev.clipboardData.files;
    if (items && items.length && ALLOWED_TYPES.has(items[0].type)) {
      ev.preventDefault();
      acceptFile(items[0]);
    }
  });

  /* ------------------------------------------------------------------ */
  /* 10. Mode switching (accessible tabs)                                */
  /* ------------------------------------------------------------------ */
  function swapField(multiline) {
    var current = field;
    if ((current.tagName === "TEXTAREA") === multiline) return;
    var next = multiline ? el("textarea", { rows: "6" }) : el("input", { type: "text" });
    ["id", "name", "class", "spellcheck", "autocapitalize", "autocorrect", "aria-describedby"]
      .forEach(function (a) { if (current.hasAttribute(a)) next.setAttribute(a, current.getAttribute(a)); });
    current.replaceWith(next);
    field = next;
    bindFieldEvents();
  }

  function setMode(mode, focus) {
    if (!Object.prototype.hasOwnProperty.call(MODES, mode)) return;
    if (state.controller) state.controller.abort();
    if (MODES[state.mode].text) state.drafts[state.mode] = field.value;
    state.mode = mode;
    var cfg = MODES[mode];

    dom.tabs.forEach(function (t) {
      var on = t.getAttribute("data-mode") === mode;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      if (on) {
        dom.form.setAttribute("aria-labelledby", t.id);
        t.scrollIntoView({ block: "nearest", inline: "nearest" });
      }
    });

    show(dom.textWrap, cfg.text);
    if (cfg.text) {
      swapField(cfg.multiline);
      field.setAttribute("maxlength", String(cfg.max));
      field.setAttribute("placeholder", cfg.placeholder);
      field.setAttribute("inputmode", mode === "phone" ? "tel" : mode === "link" ? "url" : "text");
      field.value = state.drafts[mode] || "";
      dom.label.textContent = cfg.label;
      dom.hint.textContent = cfg.hint;
      updateCount();
    }
    show(dom.uploadWrap, cfg.upload !== "none");
    if (cfg.upload !== "none") dom.uploadLabel.textContent = cfg.uploadLabel;
    show(dom.expectedWrap, mode === "slip");
    show(dom.sample, !!cfg.sample);
    if (cfg.upload === "none") clearFile();
    setFieldError("");
    resetResult();
    if (focus && cfg.text) field.focus();
  }

  dom.tabs.forEach(function (tab, i) {
    tab.addEventListener("click", function () { setMode(tab.getAttribute("data-mode"), false); });
    tab.addEventListener("keydown", function (ev) {
      var dir = ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : 0;
      if (!dir) return;
      ev.preventDefault();
      var next = dom.tabs[(i + dir + dom.tabs.length) % dom.tabs.length];
      next.focus();
      setMode(next.getAttribute("data-mode"), false);
    });
  });

  /* ------------------------------------------------------------------ */
  /* 11. Input handling                                                  */
  /* ------------------------------------------------------------------ */
  function setFieldError(msg) {
    dom.error.textContent = msg;
    if (msg) field.setAttribute("aria-invalid", "true");
    else field.removeAttribute("aria-invalid");
  }
  function updateCount() {
    var cfg = MODES[state.mode];
    if (cfg.text) dom.count.textContent = field.value.length + " / " + cfg.max;
  }

  var debounceTimer = 0;
  function onInput() {
    updateCount();
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function () {
      setFieldError(field.value.trim() ? validateText(state.mode, field.value) : "");
    }, CONFIG.debounceMs);
  }
  function onKeydown(ev) {
    if (ev.key === "Enter" && (ev.ctrlKey || ev.metaKey || field.tagName === "INPUT")) {
      ev.preventDefault();
      dom.form.requestSubmit();
    }
  }
  function bindFieldEvents() {
    field.addEventListener("input", onInput);
    field.addEventListener("keydown", onKeydown);
  }

  /* ------------------------------------------------------------------ */
  /* 12. Submit                                                          */
  /* ------------------------------------------------------------------ */
  async function submit() {
    if (state.inFlight) return;
    var now = Date.now();
    if (now - state.lastSubmitAt < CONFIG.cooldownMs) return;
    if (!CONFIG.apiBase) { renderError("CONFIG"); return; }

    var mode = state.mode;
    var cfg = MODES[mode];
    var useImage = cfg.upload === "required" || (cfg.upload === "optional" && !!state.file);
    var request;

    if (useImage) {
      if (!state.file) { dom.uploadError.textContent = "กรุณาเลือกรูปภาพก่อน"; return; }
      var form = new FormData();
      form.append("file", state.file, "upload");
      if (mode === "slip") {
        var exp = dom.expected.value.trim().replace(/,/g, "");
        if (exp) {
          if (!AMOUNT_RE.test(exp)) { dom.uploadError.textContent = ERROR_TEXT.get("INVALID_EXPECTED_AMOUNT"); return; }
          form.append("expected_amount", exp);
        }
      }
      request = { kind: "form", path: cfg.imagePath, body: form, expect: mode === "slip" ? "slip" : "trade" };
      state.lastInput = "";
    } else {
      var value = field.value.trim();
      var problem = validateText(mode, value);
      if (problem) { setFieldError(problem); field.focus(); return; }
      setFieldError("");
      var route = mode === "link" ? routeLink(value) : { path: cfg.path, field: cfg.field, mode: mode };
      var payload = {};
      payload[route.field] = value;
      request = { kind: "json", path: route.path, body: payload, expect: route.mode };
      state.lastInput = value;
    }

    state.lastSubmitAt = now;
    state.controller = new AbortController();
    var signal = state.controller.signal;
    show(dom.errorBox, false);

    try {
      if (warm.state !== "ok") {
        setLoading(true, "กำลังเตรียมระบบ");
        dom.summary.textContent = "ระบบตรวจกำลังเริ่มทำงาน อาจใช้เวลาไม่เกิน 1 นาที";
        await wakeApi();
      }
      setLoading(true, useImage ? "กำลังอ่านรูป" : "กำลังตรวจ");
      var data = request.kind === "form"
        ? await postForm(request.path, request.body, signal)
        : await postJson(request.path, request.body, signal);
      if (state.mode !== mode) return;
      if (!isValidResult(data, request.expect)) throw new ApiError("BAD_RESPONSE", false);
      renderResult(data, mode);
    } catch (err) {
      var code = err instanceof ApiError ? err.code : "NETWORK";
      if (code !== "ABORTED") renderError(code);
    } finally {
      state.controller = null;
      setLoading(false);
    }
  }

  dom.form.addEventListener("submit", function (ev) { ev.preventDefault(); submit(); });
  dom.retry.addEventListener("click", function () { state.lastSubmitAt = 0; submit(); });
  dom.sample.addEventListener("click", function () {
    var cfg = MODES[state.mode];
    if (!cfg.text || !cfg.sample) return;
    field.value = cfg.sample;
    setFieldError("");
    updateCount();
    field.focus();
  });
  dom.clear.addEventListener("click", function () {
    if (MODES[state.mode].text) { field.value = ""; state.drafts[state.mode] = ""; updateCount(); }
    dom.expected.value = "";
    clearFile();
    setFieldError("");
    resetResult();
  });

  /* ------------------------------------------------------------------ */
  /* 13. Community report form                                           */
  /* ------------------------------------------------------------------ */
  function prefillReport() {
    var v = state.lastInput || (MODES[state.mode].text ? field.value.trim() : "");
    if (!v) return;
    if (state.mode === "phone" && !dom.repPhone.value) dom.repPhone.value = v;
    if (state.mode === "link") {
      var r = routeLink(v);
      if (r.mode === "email" && !dom.repEmail.value) dom.repEmail.value = v;
      if (r.mode === "social" && !dom.repFacebook.value) dom.repFacebook.value = v;
    }
    if (state.mode === "trade" || state.mode === "sms") {
      var phone = v.match(/(?:\+66|0)[689]\d[\d\- ]{6,10}\d/);
      if (phone && !dom.repPhone.value) dom.repPhone.value = phone[0];
      var acct = v.match(/\b\d{3}-?\d-?\d{5}-?\d\b/);
      if (acct && !dom.repBank.value) dom.repBank.value = acct[0];
      var fb = v.match(/(?:https?:\/\/)?(?:www\.|m\.)?(?:facebook\.com|fb\.com)\/[^\s<>"'`]{1,200}/i);
      if (fb && !dom.repFacebook.value) dom.repFacebook.value = fb[0];
    }
  }

  function toggleReport(open) {
    show(dom.repForm, open);
    dom.repOpen.setAttribute("aria-expanded", open ? "true" : "false");
    dom.repError.textContent = "";
    show(dom.repDone, false);
    if (open) { prefillReport(); dom.repCategory.focus(); }
  }

  dom.repOpen.addEventListener("click", function () {
    toggleReport(dom.repForm.classList.contains("hidden"));
  });
  dom.repCancel.addEventListener("click", function () { toggleReport(false); });

  var reportBusy = false;
  dom.repForm.addEventListener("submit", async function (ev) {
    ev.preventDefault();
    if (reportBusy) return;
    dom.repError.textContent = "";
    var payload = { category: dom.repCategory.value, consent: true };
    var fields = [["phone", dom.repPhone], ["bank_account", dom.repBank], ["facebook", dom.repFacebook], ["email", dom.repEmail]];
    var any = false;
    for (var i = 0; i < fields.length; i++) {
      var v = fields[i][1].value.trim();
      if (!v) continue;
      if (CONTROL_RE.test(v) || URL_FORBIDDEN_RE.test(v) && fields[i][0] !== "facebook") { dom.repError.textContent = "มีอักขระที่ไม่อนุญาต"; return; }
      payload[fields[i][0]] = v;
      any = true;
    }
    if (!any) { dom.repError.textContent = ERROR_TEXT.get("NO_IDENTIFIER"); return; }
    if (!dom.repConsent.checked) { dom.repError.textContent = "กรุณาติ๊กยืนยันก่อนส่ง"; return; }
    if (!CONFIG.apiBase) { dom.repError.textContent = ERROR_TEXT.get("CONFIG"); return; }

    reportBusy = true;
    dom.repSubmit.disabled = true;
    dom.repSubmit.classList.add("is-loading");
    try {
      if (warm.state !== "ok") await wakeApi();
      var res = await postJson("/api/v1/reports", payload, null);
      if (!res || res.accepted !== true || !isInt(res.identifiers, 1, 8)) throw new ApiError("BAD_RESPONSE", false);
      dom.repDone.textContent = "ขอบคุณที่ช่วยเตือนผู้อื่น บันทึกเบาะแสแล้ว";
      show(dom.repDone, true);
      [dom.repPhone, dom.repBank, dom.repFacebook, dom.repEmail].forEach(function (n) { n.value = ""; });
      dom.repConsent.checked = false;
    } catch (err) {
      var code = err instanceof ApiError ? err.code : "NETWORK";
      dom.repError.textContent = ERROR_TEXT.get(code) || ERROR_TEXT.get("NETWORK");
    } finally {
      reportBusy = false;
      dom.repSubmit.disabled = false;
      dom.repSubmit.classList.remove("is-loading");
    }
  });

  /* ------------------------------------------------------------------ */
  /* 14. Resilience + init                                               */
  /* ------------------------------------------------------------------ */
  window.addEventListener("online", function () {
    if (!dom.errorBox.classList.contains("hidden")) dom.errorText.textContent = "กลับมาออนไลน์แล้ว กดลองอีกครั้งได้เลย";
  });
  window.addEventListener("unhandledrejection", function () { setLoading(false); });
  window.addEventListener("error", function () { setLoading(false); });

  bindFieldEvents();
  setMode("trade", false);
  wakeApi();                                // wake the sleeping free-tier API early
  Object.freeze(Object.prototype);          // blunt prototype-pollution gadgets
})();
