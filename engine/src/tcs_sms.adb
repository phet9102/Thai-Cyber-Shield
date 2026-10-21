pragma Wide_Character_Encoding (UTF8);

with TCS_Text; use TCS_Text;

package body TCS_SMS with SPARK_Mode => On is

   ---------------------------------------------------------------------------
   --  Keyword tables (matched against the COMPACT view: no spaces/fillers)
   ---------------------------------------------------------------------------
   Urgency : constant Keyword_List :=
     (KW ("ด่วน"), KW ("ด่วนที่สุด"), KW ("ภายในวันนี้"), KW ("ภายใน24"),
      KW ("ถูกระงับ"), KW ("ระงับบัญชี"), KW ("อายัด"), KW ("หมดอายุ"),
      KW ("ครั้งสุดท้าย"), KW ("แจ้งเตือนสำคัญ"), KW ("urgent"),
      KW ("suspend"), KW ("immediately"), KW ("lastwarning"));

   Money_Lure : constant Keyword_List :=
     (KW ("รับเงิน"), KW ("เงินคืน"), KW ("คืนเงิน"), KW ("โบนัส"),
      KW ("ถูกรางวัล"), KW ("รางวัล"), KW ("เครดิตฟรี"), KW ("ฟรีเครดิต"),
      KW ("แจกฟรี"), KW ("รับสิทธิ์"), KW ("สิทธิพิเศษ"), KW ("bonus"),
      KW ("prize"), KW ("winner"), KW ("reward"), KW ("freecredit"));

   Gambling : constant Keyword_List :=
     (KW ("สล็อต"), KW ("บาคาร่า"), KW ("แทงบอล"), KW ("คาสิโน"),
      KW ("เว็บตรง"), KW ("ฝากถอน"), KW ("หวยออนไลน์"), KW ("pgslot"),
      KW ("baccarat"), KW ("casino"), KW ("ufabet"), KW ("slot"));

   Loan : constant Keyword_List :=
     (KW ("สินเชื่อ"), KW ("กู้เงิน"), KW ("เงินกู้"), KW ("อนุมัติไว"),
      KW ("อนุมัติ"), KW ("วงเงิน"), KW ("ดอกเบี้ยต่ำ"), KW ("ไม่ต้องค้ำ"),
      KW ("ไม่เช็คบูโร"), KW ("ผ่อนสบาย"), KW ("loan"));

   Investment : constant Keyword_List :=
     (KW ("ลงทุน"), KW ("ผลตอบแทน"), KW ("กำไรต่อวัน"), KW ("กำไร"),
      KW ("เทรด"), KW ("คริปโต"), KW ("ปันผล"), KW ("crypto"),
      KW ("usdt"), KW ("forex"));

   Authority : constant Keyword_List :=
     (KW ("กรมสรรพากร"), KW ("สรรพากร"), KW ("ตำรวจ"), KW ("ปปง"),
      KW ("ดีเอสไอ"), KW ("dsi"), KW ("หมายจับ"), KW ("หมายศาล"),
      KW ("การไฟฟ้า"), KW ("กฟภ"), KW ("กฟน"), KW ("การประปา"),
      KW ("ประกันสังคม"), KW ("กรมที่ดิน"), KW ("กรมการขนส่ง"),
      KW ("ทางรัฐ"), KW ("เป๋าตัง"), KW ("กสทช"));

   Bank_Brand : constant Keyword_List :=
     (KW ("ธนาคาร"), KW ("กสิกร"), KW ("ไทยพาณิชย์"), KW ("กรุงไทย"),
      KW ("กรุงศรี"), KW ("ออมสิน"), KW ("ธกส"), KW ("ทีทีบี"),
      KW ("kbank"), KW ("kasikorn"), KW ("scb"), KW ("krungthai"),
      KW ("krungsri"), KW ("gsb"), KW ("ttb"));

   Parcel : constant Keyword_List :=
     (KW ("พัสดุ"), KW ("ไปรษณีย์"), KW ("ตกค้าง"), KW ("จัดส่งไม่สำเร็จ"),
      KW ("ที่อยู่ไม่ถูกต้อง"), KW ("kerry"), KW ("flashexpress"),
      KW ("thailandpost"), KW ("parcel"), KW ("delivery"));

   Credential : constant Keyword_List :=
     (KW ("ยืนยันตัวตน"), KW ("อัปเดตข้อมูล"), KW ("อัพเดทข้อมูล"),
      KW ("กรอกข้อมูล"), KW ("รหัสotp"), KW ("otp"), KW ("รหัสผ่าน"),
      KW ("เลขบัตรประชาชน"), KW ("สแกนใบหน้า"), KW ("login"),
      KW ("verify"), KW ("password"));

   Transfer : constant Keyword_List :=
     (KW ("โอนเงิน"), KW ("โอนมา"), KW ("โอนก่อน"), KW ("ค่าธรรมเนียม"),
      KW ("มัดจำ"), KW ("ภาษีคืน"), KW ("บัญชีปลอดภัย"),
      KW ("ตรวจสอบบัญชี"), KW ("ชำระค่า"), KW ("transfer"));

   Contact : constant Keyword_List :=
     (KW ("ไลน์"), KW ("แอดไลน์"), KW ("เพิ่มเพื่อน"), KW ("โทรกลับ"),
      KW ("ติดต่อกลับ"), KW ("กดลิงก์"), KW ("กดลิ้ง"), KW ("คลิก"),
      KW ("คลิ๊ก"), KW ("telegram"), KW ("whatsapp"), KW ("addline"));

   ---------------------------------------------------------------------------
   --  Structural tables (matched against the NORMAL view: punctuation kept)
   ---------------------------------------------------------------------------
   Url_Markers : constant Keyword_List :=
     (KW ("://"), KW ("www."), KW (".com"), KW (".net"), KW (".org"),
      KW (".xyz"), KW (".top"), KW (".info"), KW (".shop"), KW (".vip"),
      KW (".link"), KW (".click"), KW (".cc/"), KW (".app"), KW (".site"),
      KW (".online"), KW (".icu"), KW (".me/"), KW (".co/"), KW (".in.th"),
      KW (".co.th"));

   Shorteners : constant Keyword_List :=
     (KW ("bit.ly"), KW ("tinyurl"), KW ("cutt.ly"), KW ("shorturl"),
      KW ("t.ly/"), KW ("rb.gy"), KW ("is.gd"), KW ("s.id/"),
      KW ("rebrand.ly"), KW ("goo.gl"), KW ("ow.ly"), KW ("t.co/"),
      KW ("lin.ee"), KW ("tny.im"));

   Apk_Markers : constant Keyword_List :=
     (KW (".apk"), KW ("apk"));

   Payload_Markers : constant Keyword_List :=
     (KW ("<script"), KW ("javascript:"), KW ("onerror="), KW ("onload="),
      KW ("<iframe"), KW ("<svg"), KW ("${"), KW ("{{"), KW ("${jndi"),
      KW ("union select"), KW ("' or '1'='1"), KW ("or 1=1"),
      KW ("; drop table"), KW ("../.."), KW ("$("), KW ("`"));

   Format_Markers : constant Keyword_List :=
     (KW ("%n"), KW ("%s%s"), KW ("%x%x"), KW ("%p%p"), KW ("%08x"),
      KW ("%hn"));

   ---------------------------------------------------------------------------
   --  Helpers
   ---------------------------------------------------------------------------

   --  Diminishing returns: first hit = Base, each extra hit +3, max +9.
   procedure Score_Category
     (R : in out Analysis_Result; Hits : Natural; Code : Finding_Code;
      Base : Weight)
   is
      Extra : constant Natural := Natural'Min (Hits, 4);
   begin
      if Hits > 0 then
         Add (R, Code, Natural'Min (Base + (Extra - 1) * 3, 100));
      end if;
   end Score_Category;

   --  Detect a phone-number-like run: >= 9 digits, allowing single
   --  '-' / ' ' / '.' separators between digits.
   function Has_Phone_Run (T : Text) return Boolean is
      Digits_In_Run : Natural := 0;
      Last_Was_Sep  : Boolean := False;
   begin
      for I in 1 .. T.Len loop
         pragma Loop_Invariant (Digits_In_Run < I);
         declare
            C : constant Wide_Wide_Character := T.Data (I);
         begin
            if Is_Digit (C) then
               Digits_In_Run := Digits_In_Run + 1;
               Last_Was_Sep := False;
               if Digits_In_Run >= 9 then
                  return True;
               end if;
            elsif (C = '-' or else C = ' ' or else C = '.')
              and then Digits_In_Run > 0 and then not Last_Was_Sep
            then
               Last_Was_Sep := True;
            elsif C = '+' and then Digits_In_Run = 0 then
               null;
            else
               Digits_In_Run := 0;
               Last_Was_Sep := False;
            end if;
         end;
      end loop;
      return False;
   end Has_Phone_Run;

   -------------
   -- Analyze --
   -------------
   procedure Analyze (Input : Text; R : out Analysis_Result) is
      Normal  : Text;
      Compact : Text;

      H_Urgency, H_Money, H_Gamble, H_Loan, H_Invest, H_Auth, H_Bank,
      H_Parcel, H_Cred, H_Transfer, H_Contact : Natural;

      Has_Url, Has_Short, Has_Latin, Has_Homoglyph_Script : Boolean := False;
      Has_Invisible, Has_Bidi : Boolean := False;
   begin
      R := Empty_Result;

      if Input.Len = 0 then
         return;
      end if;

      --  1. Raw-level indicators (checked BEFORE normalisation removes them)
      for I in 1 .. Input.Len loop
         declare
            C : constant Wide_Wide_Character := Input.Data (I);
         begin
            Has_Invisible := Has_Invisible or else Is_Zero_Width (C);
            Has_Bidi      := Has_Bidi or else Is_Bidi_Control (C);
         end;
      end loop;

      if Has_Invisible then
         Add (R, F_Invisible_Chars, 25);
      end if;
      if Has_Bidi then
         Add (R, F_Bidi_Override, 30);
      end if;

      --  2. Build the two analysis views
      Normal_View (Input, Normal);
      Compact_View (Input, Compact);

      --  3. Keyword-splitting evasion ("โ อ น เ งิ น")
      if Isolated_Thai_Fragments (Normal) >= 5 then
         Add (R, F_Evasion_Spacing, 20);
      end if;

      --  4. Semantic categories
      H_Urgency  := Count_Matches (Compact, Urgency);
      H_Money    := Count_Matches (Compact, Money_Lure);
      H_Gamble   := Count_Matches (Compact, Gambling);
      H_Loan     := Count_Matches (Compact, Loan);
      H_Invest   := Count_Matches (Compact, Investment);
      H_Auth     := Count_Matches (Compact, Authority);
      H_Bank     := Count_Matches (Compact, Bank_Brand);
      H_Parcel   := Count_Matches (Compact, Parcel);
      H_Cred     := Count_Matches (Compact, Credential);
      H_Transfer := Count_Matches (Compact, Transfer);
      H_Contact  := Count_Matches (Compact, Contact);

      Score_Category (R, H_Urgency,  F_Sms_Urgency,            15);
      Score_Category (R, H_Money,    F_Sms_Money_Lure,         15);
      Score_Category (R, H_Gamble,   F_Sms_Gambling,           30);
      Score_Category (R, H_Loan,     F_Sms_Loan,               20);
      Score_Category (R, H_Invest,   F_Sms_Investment,         20);
      Score_Category (R, H_Auth,     F_Sms_Authority,          15);
      Score_Category (R, H_Bank,     F_Sms_Bank_Brand,         10);
      Score_Category (R, H_Parcel,   F_Sms_Parcel,             10);
      Score_Category (R, H_Cred,     F_Sms_Credential_Request, 20);
      Score_Category (R, H_Transfer, F_Sms_Transfer_Request,   20);
      Score_Category (R, H_Contact,  F_Sms_Contact_Channel,    10);

      --  5. Structural indicators
      Has_Url   := Count_Matches (Normal, Url_Markers) > 0;
      Has_Short := Count_Matches (Normal, Shorteners) > 0;

      if Has_Url then
         Add (R, F_Sms_Contains_Url, 15);
      end if;
      if Has_Short then
         Add (R, F_Sms_Contains_Shortener, 20);
      end if;
      if Count_Matches (Normal, Apk_Markers) > 0 then
         Add (R, F_Sms_Contains_Apk, 45);
      end if;
      if Has_Phone_Run (Normal) then
         Add (R, F_Sms_Contains_Phone, 5);
      end if;

      for I in 1 .. Normal.Len loop
         declare
            C : constant Wide_Wide_Character := Normal.Data (I);
         begin
            Has_Latin := Has_Latin or else Is_Ascii_Letter (C);
            Has_Homoglyph_Script :=
              Has_Homoglyph_Script or else Is_Cyrillic (C) or else Is_Greek (C);
         end;
      end loop;
      if Has_Latin and then Has_Homoglyph_Script then
         Add (R, F_Sms_Mixed_Script, 25);
      end if;

      --  6. Combination rules (strongest real-world predictors)
      if (H_Auth > 0 or else H_Bank > 0 or else H_Parcel > 0
          or else H_Cred > 0)
        and then (Has_Url or else Has_Short)
      then
         Add (R, F_Combo_Authority_Link, 25);
      end if;

      if H_Urgency > 0 and then (Has_Url or else Has_Short or else H_Contact > 0)
      then
         Add (R, F_Combo_Urgency_Link, 20);
      end if;

      if (H_Money > 0 or else H_Gamble > 0 or else H_Loan > 0
          or else H_Invest > 0)
        and then (H_Contact > 0 or else Has_Url or else Has_Short)
      then
         Add (R, F_Combo_Lure_Contact, 20);
      end if;

      --  7. Attack-payload telemetry (low score weight: an SMS containing
      --     code is suspicious but the value is in flagging the attempt)
      if Count_Matches (Normal, Payload_Markers) > 0 then
         Add (R, F_Payload_Pattern, 5);
      end if;
      if Count_Matches (Normal, Format_Markers) > 0 then
         Add (R, F_Format_String, 5);
      end if;
   end Analyze;

end TCS_SMS;
