/*!
 * Thai Cyber Shield - frontend controller
 *
 * Security model (see SECURITY.md for the full write-up):
 *  - NO HTML sinks: never innerHTML / outerHTML / insertAdjacentHTML /
 *    document.write / eval / new Function / string setTimeout. All output is
 *    built with createElement + textContent. CSP `require-trusted-types-for
 *    'script'; trusted-types 'none'` makes the browser itself throw if any
 *    future code tries to use an HTML sink -> DOM-XSS is blocked by policy.
 *  - API responses are untrusted: size-capped, content-type checked, parsed
 *    in try/catch and validated against a closed schema before rendering.
 *    Finding codes are only ever used as Map keys -> unknown codes are shown
 *    as a generic message, never echoed.
 *  - Anti-spam: in-flight lock, submit cooldown, debounced pre-validation,
 *    AbortController timeouts, bounded retries with jittered backoff.
 *  - Clickjacking: frame-ancestors 'none' + X-Frame-Options DENY (headers),
 *    plus this frame-buster as a fallback for very old browsers.
 *  - Nothing secret ever lives in the client. DevTools cannot be "blocked";
 *    instead we hold no secrets and warn users against self-XSS scams.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* 0. Clickjacking fallback                                           */
  /* ------------------------------------------------------------------ */
  if (window.top !== window.self) {
    try { window.top.location.replace(window.self.location.href); } catch (_) { /* sandboxed */ }
    document.documentElement.replaceChildren();
    return;
  }

  /* ------------------------------------------------------------------ */
  /* 1. Self-XSS social-engineering warning                             */
  /* ------------------------------------------------------------------ */
  try {
    console.log(
      "%cหยุดก่อน!",
      "color:#FF5D73;font-size:32px;font-weight:700"
    );
    console.log(
      "%cหากมีคนบอกให้คัดลอกโค้ดมาวางที่นี่ นั่นคือกลโกงเพื่อขโมยบัญชีของคุณ อย่าวางโค้ดใด ๆ ที่ไม่ได้เขียนเอง",
      "font-size:15px"
    );
  } catch (_) { /* console may be unavailable */ }

  /* ------------------------------------------------------------------ */
  /* 2. Configuration (frozen)                                          */
  /* ------------------------------------------------------------------ */
  function resolveApiBase() {
    var meta = document.querySelector('meta[name="tcs-api-base"]');
    var raw = meta ? meta.getAttribute("content") : "";
    try {
      var u = new URL(raw, window.location.origin);
      var local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
      if (u.protocol !== "https:" && !(local && u.protocol === "http:")) return null;
      if (u.username || u.password || u.search || u.hash) return null;
      return u.origin;               // origin only: no path tricks
    } catch (_) {
      return null;
    }
  }

  var CONFIG = Object.freeze({
    apiBase: resolveApiBase(),
    timeoutMs: 10000,
    maxRetries: 2,
    cooldownMs: 1500,
    debounceMs: 250,
    maxResponseChars: 65536
  });

  var MODES = Object.freeze({
    sms: Object.freeze({
      path: "/api/v1/analyze/sms", field: "message", max: 1000, multiline: true,
      label: "ข้อความที่ได้รับ",
      hint: "คัดลอกข้อความทั้งหมดมาวาง รวมลิงก์และเบอร์โทรในข้อความด้วย",
      placeholder: "เช่น บัญชีของท่านถูกระงับ กรุณายืนยันตัวตนที่ลิงก์…",
      sample: "แจ้งเตือนด่วน! บัญชีของท่านถูกระงับชั่วคราว กรุณายืนยันตัวตนภายในวันนี้ที่ https://bit.ly/kbank-verify มิฉะนั้นบัญชีจะถูกอายัด"
    }),
    url: Object.freeze({
      path: "/api/v1/analyze/url", field: "url", max: 2048, multiline: false,
      label: "ลิงก์ที่ต้องการตรวจ",
      hint: "วางลิงก์ทั้งบรรทัด ไม่ต้องเปิดลิงก์ก่อนตรวจ",
      placeholder: "เช่น https://scb-th-update.top/login",
      sample: "http://krungthai-refund.top/login/verify"
    }),
    phone: Object.freeze({
      path: "/api/v1/analyze/phone", field: "phone", max: 32, multiline: false,
      label: "เบอร์ที่โทรหรือส่งข้อความมา",
      hint: "พิมพ์ตามที่เห็นบนหน้าจอ รวมเครื่องหมาย + ถ้ามี",
      placeholder: "เช่น +697 123 456 789",
      sample: "+697 2 345 6789"
    })
  });

  var LEVELS = new Map([
    ["SAFE",     { label: "ไม่พบสัญญาณอันตราย", summary: "ยังไม่พบรูปแบบที่ตรงกับมิจฉาชีพ แต่ควรระวังเสมอ" }],
    ["LOW",      { label: "เสี่ยงต่ำ",           summary: "มีจุดที่ควรสังเกต ตรวจสอบกับช่องทางทางการก่อน" }],
    ["MEDIUM",   { label: "น่าสงสัย",            summary: "พบหลายสัญญาณที่มิจฉาชีพมักใช้ อย่าเพิ่งกดหรือโทรกลับ" }],
    ["HIGH",     { label: "เสี่ยงสูง",           summary: "รูปแบบตรงกับการหลอกลวงที่พบบ่อย ไม่ควรทำตาม" }],
    ["CRITICAL", { label: "อันตรายมาก",          summary: "เกือบแน่นอนว่าเป็นมิจฉาชีพ อย่ากด อย่าโทรกลับ อย่าโอนเงิน" }]
  ]);

  var ADVICE = new Map([
    ["SAFE", ["ถ้าข้อความขอข้อมูลส่วนตัวหรือให้โอนเงิน ให้ติดต่อหน่วยงานนั้นผ่านเบอร์หรือแอปทางการเอง"]],
    ["LOW", [
      "ติดต่อหน่วยงานที่อ้างถึงผ่านเบอร์บนเว็บไซต์หรือแอปทางการ ไม่ใช่เบอร์ในข้อความ",
      "อย่ากรอกรหัส OTP หรือรหัสผ่านในลิงก์ที่ได้รับ"
    ]],
    ["MEDIUM", [
      "อย่ากดลิงก์ อย่าแอด LINE และอย่าโทรกลับเบอร์ในข้อความ",
      "ถ้าเป็นเรื่องบัญชีธนาคาร ให้เปิดแอปธนาคารเองเพื่อตรวจสอบ",
      "บล็อกและรายงานเบอร์ผู้ส่งเป็นสแปม"
    ]],
    ["HIGH", [
      "ลบข้อความและบล็อกผู้ส่ง ไม่ต้องตอบกลับ",
      "ถ้ากดลิงก์หรือติดตั้งแอปไปแล้ว ให้ปิดอินเทอร์เน็ตมือถือและโทรหาธนาคารทันที",
      "แจ้งเบาะแสได้ที่สายด่วน 1441"
    ]],
    ["CRITICAL", [
      "อย่ากด อย่าโทรกลับ อย่าโอนเงิน ไม่ว่าอีกฝ่ายจะอ้างเป็นใคร",
      "ถ้าโอนเงินไปแล้ว โทร 1441 หรือธนาคารของคุณทันทีเพื่อขออายัดบัญชีปลายทาง",
      "ถ้าติดตั้งแอปจากลิงก์ไปแล้ว ให้ปิดเน็ต ถอดซิม และนำเครื่องไปตรวจที่ศูนย์บริการ"
    ]]
  ]);

  // Finding code -> [Thai explanation, severity]. Used only as lookup.
  var FINDINGS = new Map([
    ["INVISIBLE_CHARS", ["มีตัวอักษรล่องหนซ่อนอยู่ ใช้หลบระบบกรองข้อความ", "high"]],
    ["BIDI_OVERRIDE", ["มีอักขระกลับทิศทางข้อความ ใช้พรางให้ลิงก์หรือข้อความดูเหมือนของจริง", "high"]],
    ["PAYLOAD_PATTERN", ["มีรูปแบบโค้ดหรือคำสั่งโจมตีแฝงอยู่ในข้อความ", "mid"]],
    ["FORMAT_STRING", ["มีรูปแบบอักขระที่ใช้โจมตีระบบ (format string)", "mid"]],
    ["EVASION_SPACING", ["มีการแยกตัวอักษรด้วยช่องว่างหรือจุด เพื่อหลบการตรวจจับคำ", "high"]],
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
    ["URL_HOMOGLYPH", ["ชื่อเว็บผสมตัวอักษรต่างภาษาที่หน้าตาเหมือนกัน (เว็บปลอมเลียนแบบ)", "high"]],
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
    ["PH_INVALID_FORMAT", ["มีตัวอักษรหรือสัญลักษณ์ที่ไม่ใช่เบอร์โทร", "high"]]
  ]);

  var ERROR_TEXT = new Map([
    ["RATE_LIMITED", "ตรวจถี่เกินไป รอสักครู่แล้วลองใหม่"],
    ["INVALID_INPUT", "รูปแบบข้อมูลไม่ถูกต้อง ตรวจสอบสิ่งที่วางแล้วลองใหม่"],
    ["INPUT_TOO_LONG", "ข้อความยาวเกินกำหนด"],
    ["INPUT_INVALID_UTF8", "ข้อความมีอักขระที่อ่านไม่ได้"],
    ["INPUT_FORBIDDEN_CONTROL", "ข้อความมีอักขระควบคุมที่ไม่อนุญาต"],
    ["PAYLOAD_TOO_LARGE", "ข้อมูลใหญ่เกินกำหนด"],
    ["SERVICE_UNAVAILABLE", "ระบบตรวจไม่ว่างชั่วคราว ลองใหม่อีกครั้งในไม่กี่วินาที"],
    ["TIMEOUT", "เชื่อมต่อนานเกินไป ตรวจสอบอินเทอร์เน็ตแล้วลองใหม่"],
    ["OFFLINE", "ไม่ได้เชื่อมต่ออินเทอร์เน็ต เชื่อมต่อแล้วลองใหม่"],
    ["NETWORK", "เชื่อมต่อระบบตรวจไม่ได้ ลองใหม่อีกครั้ง"],
    ["BAD_RESPONSE", "ได้รับผลตอบกลับที่ไม่ถูกต้อง ระบบปฏิเสธการแสดงผลเพื่อความปลอดภัย"],
    ["CONFIG", "ตั้งค่าที่อยู่ระบบตรวจไม่ถูกต้อง (ผู้ดูแลต้องแก้ tcs-api-base)"]
  ]);

  /* ------------------------------------------------------------------ */
  /* 3. Client-side pre-validation (mirrors the API; UX only - the      */
  /*    server re-validates everything)                                 */
  /* ------------------------------------------------------------------ */
  var CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;
  var URL_FORBIDDEN_RE = /[<>"`{}\\^|]/;
  var PHONE_RE = /^[+＋0-9๐-๙０-９ ()\-./]{3,32}$/;
  var LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/;

  function validate(mode, value) {
    var cfg = MODES[mode];
    var v = value.trim();
    if (!v) return "กรุณาวางสิ่งที่ต้องการตรวจ";
    if (v.length > cfg.max) return "ยาวเกิน " + cfg.max + " ตัวอักษร";
    if (LONE_SURROGATE_RE.test(v)) return "มีอักขระที่ไม่ถูกต้อง";
    if (CONTROL_RE.test(v.replace(/[\t\n\r]/g, ""))) return "มีอักขระควบคุมที่ไม่อนุญาต";
    if (mode === "url" && URL_FORBIDDEN_RE.test(v)) return "ลิงก์มีอักขระที่ใช้ในลิงก์ไม่ได้ เช่น < > \" `";
    if (mode === "phone") {
      if (!PHONE_RE.test(v)) return "ใส่ได้เฉพาะตัวเลข + ( ) - และช่องว่าง";
      var digits = v.replace(/[^0-9๐-๙０-９]/g, "").length;
      if (digits < 3) return "ตัวเลขน้อยเกินไป";
    }
    return "";
  }

  /* ------------------------------------------------------------------ */
  /* 4. Response validation (zero trust)                                */
  /* ------------------------------------------------------------------ */
  var CODE_RE = /^[A-Z0-9_]{1,40}$/;
  var HOST_RE = /^[a-z0-9.:\-]{1,253}$/;

  function isValidResult(o, mode) {
    if (!o || typeof o !== "object" || Array.isArray(o)) return false;
    if (o.mode !== mode) return false;
    if (typeof o.score !== "number" || !Number.isInteger(o.score) || o.score < 0 || o.score > 100) return false;
    if (typeof o.level !== "string" || !LEVELS.has(o.level)) return false;
    if (!Array.isArray(o.findings) || o.findings.length > 24) return false;
    for (var i = 0; i < o.findings.length; i++) {
      if (typeof o.findings[i] !== "string" || !CODE_RE.test(o.findings[i])) return false;
    }
    if (o.host !== null && o.host !== undefined &&
        (typeof o.host !== "string" || !HOST_RE.test(o.host))) return false;
    return true;
  }

  function safeErrorCode(o) {
    if (o && typeof o === "object" && typeof o.error === "string" && CODE_RE.test(o.error)) {
      return o.error;
    }
    return "";
  }

  /* ------------------------------------------------------------------ */
  /* 5. Network layer: timeout, bounded retry, size cap                 */
  /* ------------------------------------------------------------------ */
  function ApiError(code, retryable) {
    this.code = code;
    this.retryable = !!retryable;
  }

  function sleep(ms) {
    return new Promise(function (resolve) { setTimeout(resolve, ms); });
  }

  async function postOnce(path, payload, outerSignal) {
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, CONFIG.timeoutMs);
    var onOuterAbort = function () { ctrl.abort(); };
    if (outerSignal) outerSignal.addEventListener("abort", onOuterAbort, { once: true });

    try {
      var res;
      try {
        res = await fetch(CONFIG.apiBase + path, {
          method: "POST",
          mode: "cors",
          credentials: "omit",          // never send cookies cross-origin
          cache: "no-store",
          redirect: "error",            // a redirect is never legitimate here
          referrerPolicy: "no-referrer",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
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

      var body;
      try { body = JSON.parse(text); } catch (_) { throw new ApiError("BAD_RESPONSE", false); }

      if (res.ok) return body;

      var code = safeErrorCode(body);
      if (res.status === 429) throw new ApiError("RATE_LIMITED", false);
      if (res.status >= 500) throw new ApiError("SERVICE_UNAVAILABLE", true);
      throw new ApiError(ERROR_TEXT.has(code) ? code : "INVALID_INPUT", false);
    } finally {
      clearTimeout(timer);
      if (outerSignal) outerSignal.removeEventListener("abort", onOuterAbort);
    }
  }

  async function postWithRetry(path, payload, signal) {
    var attempt = 0;
    for (;;) {
      try {
        return await postOnce(path, payload, signal);
      } catch (err) {
        var e = err instanceof ApiError ? err : new ApiError("NETWORK", true);
        if (!e.retryable || attempt >= CONFIG.maxRetries || (signal && signal.aborted)) throw e;
        attempt += 1;
        // exponential backoff with full jitter: 0..(400 * 2^n) ms
        await sleep(Math.floor(Math.random() * 400 * Math.pow(2, attempt)));
      }
    }
  }

  /* ------------------------------------------------------------------ */
  /* 6. DOM helpers - textContent only                                  */
  /* ------------------------------------------------------------------ */
  function $(id) { return document.getElementById(id); }

  function el(tag, attrs, text) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) { node.setAttribute(k, attrs[k]); });
    }
    if (text !== undefined) node.textContent = text;   // never parsed as HTML
    return node;
  }

  function show(node, visible) { node.classList.toggle("hidden", !visible); }

  var dom = {
    tabs: Array.prototype.slice.call(document.querySelectorAll('[role="tab"]')),
    form: $("checker-form"),
    label: $("field-label"),
    hint: $("field-hint"),
    count: $("field-count"),
    error: $("field-error"),
    submit: $("submit-btn"),
    sample: $("sample-btn"),
    clear: $("clear-btn"),
    result: $("result"),
    arc: $("gauge-arc"),
    score: $("gauge-score"),
    level: $("result-level"),
    summary: $("result-summary"),
    host: $("result-host"),
    reasonsWrap: $("reasons-wrap"),
    reasons: $("reasons"),
    advice: $("advice"),
    adviceList: $("advice-list"),
    errorBox: $("error-box"),
    errorText: $("error-text"),
    retry: $("retry-btn")
  };
  var field = $("field-text");
  var ARC_LEN = 326.73;          // 2 * PI * 52

  /* ------------------------------------------------------------------ */
  /* 7. State                                                           */
  /* ------------------------------------------------------------------ */
  var state = {
    mode: "sms",
    inFlight: false,
    lastSubmitAt: 0,
    controller: null,
    drafts: { sms: "", url: "", phone: "" }
  };

  /* ------------------------------------------------------------------ */
  /* 8. Rendering                                                       */
  /* ------------------------------------------------------------------ */
  function resetResult() {
    dom.result.setAttribute("data-level", "IDLE");
    dom.arc.setAttribute("stroke-dashoffset", String(ARC_LEN));
    dom.score.textContent = "—";
    dom.level.textContent = "ยังไม่ได้ตรวจ";
    dom.summary.textContent = "ผลจะแสดงที่นี่ พร้อมเหตุผลและสิ่งที่ควรทำต่อ";
    dom.reasons.replaceChildren();
    dom.adviceList.replaceChildren();
    show(dom.host, false);
    show(dom.reasonsWrap, false);
    show(dom.advice, false);
    show(dom.errorBox, false);
  }

  function renderResult(data) {
    var level = LEVELS.get(data.level);
    show(dom.errorBox, false);

    dom.result.setAttribute("data-level", data.level);
    dom.arc.setAttribute("stroke-dashoffset", String(ARC_LEN * (1 - data.score / 100)));
    dom.score.textContent = String(data.score);
    dom.level.textContent = level.label;
    dom.summary.textContent = level.summary;

    if (data.host) {
      dom.host.textContent = "ปลายทางจริงของลิงก์: " + data.host;
      show(dom.host, true);
    } else {
      show(dom.host, false);
    }

    var items = [];
    data.findings.forEach(function (code) {
      var f = FINDINGS.get(code) || ["พบความผิดปกติอื่น", "mid"];
      var li = el("li");
      li.appendChild(el("span", { "class": "reason-dot", "data-sev": f[1], "aria-hidden": "true" }));
      li.appendChild(el("span", null, f[0]));
      items.push(li);
    });
    dom.reasons.replaceChildren.apply(dom.reasons, items);
    show(dom.reasonsWrap, items.length > 0);

    var adv = (ADVICE.get(data.level) || []).map(function (t) { return el("li", null, t); });
    dom.adviceList.replaceChildren.apply(dom.adviceList, adv);
    show(dom.advice, adv.length > 0);

    dom.result.classList.remove("reveal");
    void dom.result.offsetWidth;          // restart the single reveal animation
    dom.result.classList.add("reveal");
  }

  function renderError(code) {
    dom.errorText.textContent = ERROR_TEXT.get(code) || ERROR_TEXT.get("NETWORK");
    show(dom.errorBox, true);
    show(dom.retry, code !== "INVALID_INPUT" && code !== "CONFIG" && code !== "INPUT_TOO_LONG");
  }

  function setLoading(on) {
    state.inFlight = on;
    dom.submit.disabled = on;
    dom.submit.classList.toggle("is-loading", on);
    dom.submit.querySelector(".btn-label").textContent = on ? "กำลังตรวจ" : "ตรวจเลย";
    dom.result.setAttribute("aria-busy", on ? "true" : "false");
  }

  /* ------------------------------------------------------------------ */
  /* 9. Mode switching (accessible tabs)                                */
  /* ------------------------------------------------------------------ */
  function swapField(multiline) {
    var current = field;
    var wantTextarea = multiline;
    if ((current.tagName === "TEXTAREA") === wantTextarea) return;
    var next = wantTextarea ? el("textarea", { rows: "6" }) : el("input", { type: "text" });
    ["id", "name", "class", "spellcheck", "autocapitalize", "autocorrect", "aria-describedby", "required"]
      .forEach(function (a) { if (current.hasAttribute(a)) next.setAttribute(a, current.getAttribute(a)); });
    current.replaceWith(next);
    field = next;
    bindFieldEvents();
  }

  function setMode(mode, focus) {
    if (!Object.prototype.hasOwnProperty.call(MODES, mode)) return;
    if (state.controller) state.controller.abort();
    state.drafts[state.mode] = field.value;
    state.mode = mode;
    var cfg = MODES[mode];

    dom.tabs.forEach(function (t) {
      var on = t.getAttribute("data-mode") === mode;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      if (on) dom.form.setAttribute("aria-labelledby", t.id);
    });

    swapField(cfg.multiline);
    field.setAttribute("maxlength", String(cfg.max));
    field.setAttribute("placeholder", cfg.placeholder);
    field.setAttribute("inputmode", mode === "phone" ? "tel" : mode === "url" ? "url" : "text");
    field.value = state.drafts[mode];
    dom.label.textContent = cfg.label;
    dom.hint.textContent = cfg.hint;
    setFieldError("");
    updateCount();
    resetResult();
    if (focus) field.focus();
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
  /* 10. Input handling: counter + debounced pre-validation             */
  /* ------------------------------------------------------------------ */
  function setFieldError(msg) {
    dom.error.textContent = msg;
    if (msg) field.setAttribute("aria-invalid", "true");
    else field.removeAttribute("aria-invalid");
  }

  function updateCount() {
    dom.count.textContent = field.value.length + " / " + MODES[state.mode].max;
  }

  var debounceTimer = 0;
  function onInput() {
    updateCount();
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function () {
      setFieldError(field.value.trim() ? validate(state.mode, field.value) : "");
    }, CONFIG.debounceMs);
  }

  function onKeydown(ev) {
    // Ctrl/Cmd+Enter submits from the textarea; Enter submits single-line inputs
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
  /* 11. Submit: in-flight lock + cooldown (anti double-submit / spam)  */
  /* ------------------------------------------------------------------ */
  async function submit() {
    if (state.inFlight) return;
    var now = Date.now();
    if (now - state.lastSubmitAt < CONFIG.cooldownMs) return;

    if (!CONFIG.apiBase) { renderError("CONFIG"); return; }

    var mode = state.mode;
    var cfg = MODES[mode];
    var value = field.value.trim();
    var problem = validate(mode, value);
    if (problem) { setFieldError(problem); field.focus(); return; }
    setFieldError("");

    state.lastSubmitAt = now;
    state.controller = new AbortController();
    var payload = {};
    payload[cfg.field] = value;

    setLoading(true);
    show(dom.errorBox, false);
    try {
      var data = await postWithRetry(cfg.path, payload, state.controller.signal);
      if (state.mode !== mode) return;               // user switched tab meanwhile
      if (!isValidResult(data, mode)) throw new ApiError("BAD_RESPONSE", false);
      renderResult(data);
    } catch (err) {
      var code = err instanceof ApiError ? err.code : "NETWORK";
      if (code !== "ABORTED") renderError(code);
    } finally {
      state.controller = null;
      setLoading(false);
    }
  }

  dom.form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    submit();
  });
  dom.retry.addEventListener("click", function () {
    state.lastSubmitAt = 0;
    submit();
  });
  dom.sample.addEventListener("click", function () {
    field.value = MODES[state.mode].sample;
    setFieldError("");
    updateCount();
    field.focus();
  });
  dom.clear.addEventListener("click", function () {
    field.value = "";
    state.drafts[state.mode] = "";
    setFieldError("");
    updateCount();
    resetResult();
    field.focus();
  });

  window.addEventListener("online", function () {
    if (!dom.errorBox.classList.contains("hidden")) dom.errorText.textContent = "กลับมาออนไลน์แล้ว กดลองอีกครั้งได้เลย";
  });

  // Last-resort guard: an unexpected error must never leave the UI stuck.
  window.addEventListener("unhandledrejection", function () { setLoading(false); });
  window.addEventListener("error", function () { setLoading(false); });

  /* ------------------------------------------------------------------ */
  /* 12. Init                                                           */
  /* ------------------------------------------------------------------ */
  Object.freeze(Object.prototype);       // blunt prototype-pollution gadgets
  bindFieldEvents();
  setMode("sms", false);
})();
