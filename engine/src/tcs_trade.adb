pragma Wide_Character_Encoding (UTF8);

with TCS_Text; use TCS_Text;

package body TCS_Trade with SPARK_Mode => On is

   ---------------------------------------------------------------------------
   --  Keyword tables - matched against the COMPACT view (no spaces/fillers)
   ---------------------------------------------------------------------------
   Pay_First : constant Keyword_List :=
     (KW ("โอนก่อน"), KW ("จ่ายก่อน"), KW ("โอนก่อนส่ง"), KW ("โอนมาก่อน"),
      KW ("ชำระก่อน"), KW ("มัดจำก่อน"), KW ("โอนเต็ม"), KW ("payfirst"));

   Refuse_Escrow : constant Keyword_List :=
     (KW ("ไม่รับกลาง"), KW ("ไม่ใช้กลาง"), KW ("ไม่ผ่านกลาง"),
      KW ("ไม่มีกลาง"), KW ("ไม่ต้องใช้กลาง"), KW ("ไม่เอากลาง"),
      KW ("ไม่ใช้คนกลาง"), KW ("noescrow"), KW ("nomiddleman"));

   Fake_Escrow : constant Keyword_List :=
     (KW ("กลางของผม"), KW ("กลางของเรา"), KW ("กลางของหนู"),
      KW ("คนกลางของผม"), KW ("คนกลางของเรา"), KW ("แอดมินกลาง"),
      KW ("กลางส่วนตัว"), KW ("เว็บกลาง"), KW ("ระบบกลาง"),
      KW ("กลางประจำ"), KW ("ใช้กลางผม"), KW ("ทีมกลาง"),
      KW ("escrowsite"), KW ("myescrow"), KW ("mymiddleman"));

   Urgency : constant Keyword_List :=
     (KW ("มีคนรอ"), KW ("มีคนจอง"), KW ("คนรอเยอะ"), KW ("เหลือชิ้นสุดท้าย"),
      KW ("เหลือชิ้นเดียว"), KW ("วันนี้เท่านั้น"), KW ("รีบโอน"), KW ("ด่วน"),
      KW ("ภายใน5นาที"), KW ("ภายใน10นาที"), KW ("ไม่งั้นขายคนอื่น"),
      KW ("lastone"), KW ("hurry"));

   Too_Good : constant Keyword_List :=
     (KW ("ถูกกว่าตลาด"), KW ("ต่ำกว่าตลาด"), KW ("ขายขาดทุน"),
      KW ("ปล่อยถูก"), KW ("ขายถูกมาก"), KW ("ราคาพิเศษเฉพาะ"),
      KW ("ลดให้ถ้าโอน"), KW ("ของแท้100"), KW ("ของเถื่อน"));

   Credential : constant Keyword_List :=
     (KW ("ขอรหัส"), KW ("ส่งรหัส"), KW ("รหัสผ่าน"), KW ("รหัสเกม"),
      KW ("รหัสotp"), KW ("otp"), KW ("อีเมลผูก"), KW ("เปลี่ยนอีเมล"),
      KW ("ปลดผูก"), KW ("ผูกบัญชี"), KW ("ยืนยันตัวตน"), KW ("โค้ดยืนยัน"),
      KW ("password"), KW ("verificationcode"));

   Off_Platform : constant Keyword_List :=
     (KW ("ทักไลน์"), KW ("แอดไลน์"), KW ("เพิ่มไลน์"), KW ("คุยในไลน์"),
      KW ("ไปคุยต่อ"), KW ("คุยนอกแอป"), KW ("telegram"), KW ("เทเลแกรม"),
      KW ("whatsapp"), KW ("linee"), KW ("lineme"));

   Third_Party : constant Keyword_List :=
     (KW ("บัญชีแม่"), KW ("บัญชีพ่อ"), KW ("บัญชีเพื่อน"), KW ("บัญชีแฟน"),
      KW ("บัญชีญาติ"), KW ("บัญชีคนอื่น"), KW ("ชื่อบัญชีไม่ตรง"),
      KW ("ยืมบัญชี"), KW ("บัญชีน้อง"), KW ("บัญชีพี่"));

   Overpay : constant Keyword_List :=
     (KW ("โอนเกิน"), KW ("โอนผิด"), KW ("คืนส่วนต่าง"), KW ("โอนคืน"),
      KW ("ทอนเงิน"), KW ("เงินเกิน"), KW ("refund"));

   Fee_Trap : constant Keyword_List :=
     (KW ("ค่าธรรมเนียม"), KW ("ค่าปลดล็อก"), KW ("ค่ายืนยัน"),
      KW ("ค่าประกัน"), KW ("ค่ามัดจำ"), KW ("ค่าภาษี"), KW ("ค่าดำเนินการ"),
      KW ("ปลดล็อกบัญชี"), KW ("เงินติดระบบ"), KW ("unlockfee"));

   Angpao : constant Keyword_List :=
     (KW ("อั่งเปา"), KW ("ซองของขวัญ"), KW ("ซองทรู"), KW ("gifttruemoney"),
      KW ("ซองอั่งเปา"), KW ("ลิงก์ซอง"));

   Slip_Excuse : constant Keyword_List :=
     (KW ("สลิปไม่เข้า"), KW ("เงินไม่เข้า"), KW ("ระบบดีเลย์"),
      KW ("ธนาคารล่ม"), KW ("รอเงินเข้า"), KW ("โอนแล้วนะ"),
      KW ("เช็คสลิป"), KW ("ส่งสลิปแล้ว"), KW ("ยอดค้าง"));

   Threat : constant Keyword_List :=
     (KW ("แจ้งความ"), KW ("ฟ้อง"), KW ("ดำเนินคดี"), KW ("ประจาน"),
      KW ("ขึ้นบัญชีดำ"), KW ("แบนถาวร"), KW ("โดนจับ"));

   Game_Context : constant Keyword_List :=
     (KW ("ไอดีเกม"), KW ("ขายไอดี"), KW ("rov"), KW ("freefire"),
      KW ("roblox"), KW ("robux"), KW ("เพชร"), KW ("สกิน"),
      KW ("genshin"), KW ("valorant"), KW ("steam"), KW ("pubg"),
      KW ("ไอเทม"), KW ("เติมเกม"));

   --  Matched against NORMAL view (punctuation kept)
   Link_Markers : constant Keyword_List :=
     (KW ("://"), KW ("www."), KW (".com"), KW (".net"), KW (".xyz"),
      KW (".top"), KW (".shop"), KW (".site"), KW (".online"), KW (".link"));

   ---------------------------------------------------------------------------
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

   --  Thai bank account numbers: 10 digits, often written x-x-x groups
   --  (e.g. 123-4-56789-0).  We count a run of exactly 10..12 digits that
   --  may contain '-' or ' ' separators.
   function Has_Account_Number (T : Text) return Boolean is
      Count    : Natural := 0;
      Last_Sep : Boolean := False;
   begin
      for I in 1 .. T.Len loop
         pragma Loop_Invariant (Count < I);
         declare
            C : constant Wide_Wide_Character := T.Data (I);
         begin
            if Is_Digit (C) then
               Count := Count + 1;
               Last_Sep := False;
            elsif (C = '-' or else C = ' ') and then Count > 0
              and then not Last_Sep
            then
               Last_Sep := True;
            else
               if Count in 10 .. 12 then
                  return True;
               end if;
               Count := 0;
               Last_Sep := False;
            end if;
         end;
      end loop;
      return Count in 10 .. 12;
   end Has_Account_Number;

   -------------
   -- Analyze --
   -------------
   procedure Analyze (Input : Text; R : out Analysis_Result) is
      Normal  : Text;
      Compact : Text;

      H_Pay, H_Refuse, H_Fake, H_Urgent, H_Good, H_Cred, H_Off, H_Third,
      H_Over, H_Fee, H_Angpao, H_Excuse, H_Threat, H_Game : Natural;

      Has_Link      : Boolean;
      Has_Invisible : Boolean := False;
   begin
      R := Empty_Result;
      if Input.Len = 0 then
         return;
      end if;

      for I in 1 .. Input.Len loop
         if Is_Zero_Width (Input.Data (I)) or else Is_Bidi_Control (Input.Data (I))
         then
            Has_Invisible := True;
         end if;
      end loop;
      if Has_Invisible then
         Add (R, F_Invisible_Chars, 20);
      end if;

      Normal_View (Input, Normal);
      Compact_View (Input, Compact);

      if Isolated_Thai_Fragments (Normal) >= 5 then
         Add (R, F_Evasion_Spacing, 15);
      end if;

      H_Pay    := Count_Matches (Compact, Pay_First);
      H_Refuse := Count_Matches (Compact, Refuse_Escrow);
      H_Fake   := Count_Matches (Compact, Fake_Escrow);
      H_Urgent := Count_Matches (Compact, Urgency);
      H_Good   := Count_Matches (Compact, Too_Good);
      H_Cred   := Count_Matches (Compact, Credential);
      H_Off    := Count_Matches (Compact, Off_Platform);
      H_Third  := Count_Matches (Compact, Third_Party);
      H_Over   := Count_Matches (Compact, Overpay);
      H_Fee    := Count_Matches (Compact, Fee_Trap);
      H_Angpao := Count_Matches (Compact, Angpao);
      H_Excuse := Count_Matches (Compact, Slip_Excuse);
      H_Threat := Count_Matches (Compact, Threat);
      H_Game   := Count_Matches (Compact, Game_Context);
      Has_Link := Count_Matches (Normal, Link_Markers) > 0;

      Score_Category (R, H_Pay,    F_Tr_Pay_First,           15);
      Score_Category (R, H_Refuse, F_Tr_Refuse_Escrow,       30);
      Score_Category (R, H_Fake,   F_Tr_Fake_Escrow,         40);
      Score_Category (R, H_Urgent, F_Tr_Urgency,             10);
      Score_Category (R, H_Good,   F_Tr_Too_Good,            15);
      Score_Category (R, H_Cred,   F_Tr_Credential_Request,  35);
      Score_Category (R, H_Off,    F_Tr_Off_Platform,        15);
      Score_Category (R, H_Third,  F_Tr_Third_Party_Account, 30);
      Score_Category (R, H_Over,   F_Tr_Overpay_Refund,      35);
      Score_Category (R, H_Fee,    F_Tr_Fee_Trap,            35);
      Score_Category (R, H_Angpao, F_Tr_Angpao_Payment,      20);
      Score_Category (R, H_Excuse, F_Tr_Slip_Excuse,         20);
      Score_Category (R, H_Threat, F_Tr_Pressure_Threat,     15);

      if H_Game > 0 then
         Add (R, F_Tr_Game_Context, 0);              --  context only
      end if;
      if Has_Account_Number (Normal) then
         Add (R, F_Tr_Contains_Account_No, 5);
      end if;

      --  Combination rules: the strongest predictors seen in practice
      if H_Pay > 0 and then H_Refuse > 0 then
         Add (R, F_Combo_Pay_First_No_Escrow, 25);
      end if;
      if H_Fake > 0 and then (Has_Link or else H_Off > 0) then
         Add (R, F_Combo_Escrow_Link, 25);
      end if;
      if H_Cred > 0 and then (H_Urgent > 0 or else H_Threat > 0) then
         Add (R, F_Combo_Takeover_Urgency, 20);
      end if;
   end Analyze;

end TCS_Trade;
