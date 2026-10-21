with TCS_Text; use TCS_Text;

package body TCS_Slip with SPARK_Mode => On is

   ---------------------------------------------------------------------------
   --  Bounded ASCII fields
   ---------------------------------------------------------------------------
   Max_Val : constant := 512;
   subtype Val_Len   is Natural  range 0 .. Max_Val;
   subtype Val_Index is Positive range 1 .. Max_Val;
   type Val_Buf is array (Val_Index) of Character;

   type Field is record
      Data    : Val_Buf := (others => ' ');
      Len     : Val_Len := 0;
      Present : Boolean := False;
   end record;

   Empty_Field : constant Field :=
     (Data => (others => ' '), Len => 0, Present => False);

   type Field_Kind is
     (K_Bank, K_Ref, K_Amount, K_Expected, K_Time, K_Now, K_Qr,
      K_Edited, K_Inconsistent, K_Dup, K_Ocr_Conf);

   type Field_Set is array (Field_Kind) of Field;

   function Key_Name (K : Field_Kind) return String is
     (case K is
         when K_Bank         => "bank",
         when K_Ref          => "ref",
         when K_Amount       => "amount",
         when K_Expected     => "expected",
         when K_Time         => "time",
         when K_Now          => "now",
         when K_Qr           => "qr",
         when K_Edited       => "edited",
         when K_Inconsistent => "inconsistent",
         when K_Dup          => "dup",
         when K_Ocr_Conf     => "ocr_conf");

   --  Per-field maximum value length (anything longer = hostile input)
   function Max_Len_Of (K : Field_Kind) return Val_Len is
     (case K is
         when K_Qr                         => 512,
         when K_Ref                        => 40,
         when K_Bank                       => 12,
         when K_Amount | K_Expected        => 16,
         when K_Time | K_Now               => 12,
         when K_Edited | K_Inconsistent
            | K_Dup                        => 1,
         when K_Ocr_Conf                   => 3);

   LF : constant Wide_Wide_Character := Wide_Wide_Character'Val (10);
   CR : constant Wide_Wide_Character := Wide_Wide_Character'Val (13);

   ---------------------------------------------------------------------------
   --  Small helpers
   ---------------------------------------------------------------------------
   function Is_Dig (C : Character) return Boolean is (C in '0' .. '9');

   function Dig (C : Character) return Natural is
     (if C in '0' .. '9' then Character'Pos (C) - Character'Pos ('0') else 0);

   function Up (C : Character) return Character is
     (if C in 'a' .. 'z'
      then Character'Val (Character'Pos (C) - 32) else C);

   function Equals (F : Field; S : String) return Boolean is
   begin
      if not F.Present or else F.Len /= S'Length then
         return False;
      end if;
      for J in 0 .. S'Length - 1 loop
         if F.Data (1 + J) /= S (S'First + J) then
            return False;
         end if;
      end loop;
      return True;
   end Equals;

   function All_Digits (F : Field) return Boolean is
   begin
      if not F.Present or else F.Len = 0 then
         return False;
      end if;
      for I in 1 .. F.Len loop
         if not Is_Dig (F.Data (I)) then
            return False;
         end if;
      end loop;
      return True;
   end All_Digits;

   function Key_Equals
     (T : Text; First : Positive; Last : Natural; S : String) return Boolean
   is
   begin
      if Last > T.Len or else Last < First
        or else Last - First + 1 /= S'Length
      then
         return False;
      end if;
      for J in 0 .. S'Length - 1 loop
         if Code (T.Data (First + J)) /= Character'Pos (S (S'First + J)) then
            return False;
         end if;
      end loop;
      return True;
   end Key_Equals;

   ---------------------------------------------------------------------------
   --  Strict line parser:  key=value\n   (ASCII 0x21..0x7E values only)
   ---------------------------------------------------------------------------
   procedure Parse_Line
     (T     : Text;
      First : Positive;
      Last  : Natural;
      F     : in out Field_Set;
      Ok    : in out Boolean)
     with Pre => Last <= T.Len
   is
      L     : Natural := Last;
      Eq    : Natural := 0;
      Kind  : Field_Kind := K_Bank;
      Found : Boolean := False;
   begin
      if L >= First and then T.Data (L) = CR then
         L := L - 1;                                    --  tolerate CRLF
      end if;
      if L < First then
         return;                                        --  blank line
      end if;

      for I in First .. L loop
         if T.Data (I) = '=' then
            Eq := I;
            exit;
         end if;
      end loop;
      if Eq = 0 or else Eq = First then
         Ok := False;
         return;
      end if;

      for K in Field_Kind loop
         if Key_Equals (T, First, Eq - 1, Key_Name (K)) then
            Kind  := K;
            Found := True;
            exit;
         end if;
      end loop;

      if not Found or else F (Kind).Present then          --  unknown / duplicate key
         Ok := False;
         return;
      end if;
      if L - Eq > Max_Len_Of (Kind) then
         Ok := False;
         return;
      end if;

      F (Kind).Present := True;
      F (Kind).Len := 0;
      for I in Eq + 1 .. L loop
         pragma Loop_Invariant (F (Kind).Len = I - Eq - 1);
         pragma Loop_Invariant (F (Kind).Len < Max_Len_Of (Kind));
         declare
            P : constant Natural := Code (T.Data (I));
         begin
            if P < 16#21# or else P > 16#7E# then
               Ok := False;
               return;
            end if;
            F (Kind).Len := F (Kind).Len + 1;
            F (Kind).Data (F (Kind).Len) := Character'Val (P);
         end;
      end loop;
   end Parse_Line;

   procedure Parse (T : Text; F : out Field_Set; Ok : out Boolean) is
      Line_Start : Natural := 1;
      I          : Natural;
   begin
      F  := (others => Empty_Field);
      Ok := True;

      for J in 1 .. T.Len loop
         if Code (T.Data (J)) > 16#7E# then
            Ok := False;                                --  ASCII only
            return;
         end if;
      end loop;

      while Line_Start <= T.Len loop
         pragma Loop_Invariant (Line_Start >= 1);
         I := Line_Start;
         while I <= T.Len and then T.Data (I) /= LF loop
            pragma Loop_Invariant (I >= Line_Start and then I <= T.Len);
            I := I + 1;
         end loop;
         Parse_Line (T, Line_Start, I - 1, F, Ok);
         if not Ok then
            return;
         end if;
         Line_Start := I + 1;
      end loop;
   end Parse;

   ---------------------------------------------------------------------------
   --  Amount in satang - integer arithmetic only, overflow impossible:
   --  at most 11 integer digits + 2 decimals < 10**13.
   ---------------------------------------------------------------------------
   type Satang is range 0 .. 9_999_999_999_999;

   procedure Parse_Amount (F : Field; V : out Satang; Ok : out Boolean) is
      Int_Digits  : Natural := 0;
      Frac_Digits : Natural := 0;
      Seen_Dot    : Boolean := False;
      Acc         : Satang  := 0;
   begin
      V  := 0;
      Ok := False;
      if not F.Present or else F.Len = 0 then
         return;
      end if;

      for I in 1 .. F.Len loop
         pragma Loop_Invariant (Int_Digits <= 11 and then Frac_Digits <= 2);
         declare
            C : constant Character := F.Data (I);
         begin
            if C = '.' then
               if Seen_Dot or else Int_Digits = 0 then
                  return;
               end if;
               Seen_Dot := True;
            elsif Is_Dig (C) then
               if Seen_Dot then
                  if Frac_Digits = 2 then
                     return;
                  end if;
                  Frac_Digits := Frac_Digits + 1;
               else
                  if Int_Digits = 11 then
                     return;
                  end if;
                  Int_Digits := Int_Digits + 1;
               end if;
               Acc := Acc * 10 + Satang (Dig (C));
            else
               return;
            end if;
         end;
      end loop;

      if Int_Digits = 0 or else (Seen_Dot and then Frac_Digits = 0) then
         return;
      end if;

      if Frac_Digits = 0 then
         Acc := Acc * 100;
      elsif Frac_Digits = 1 then
         Acc := Acc * 10;
      end if;

      V  := Acc;
      Ok := True;
   end Parse_Amount;

   ---------------------------------------------------------------------------
   --  Gregorian yyyymmddhhmm -> minutes since 2000-01-01 00:00
   --  (years 2000..2100 => < 54 million minutes, fits Natural)
   ---------------------------------------------------------------------------
   function Is_Leap (Y : Natural) return Boolean is
     ((Y mod 4 = 0 and then Y mod 100 /= 0) or else Y mod 400 = 0);

   function Days_In (Y : Natural; M : Positive) return Natural is
     (case M is
         when 1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
         when 4 | 6 | 9 | 11              => 30,
         when 2                           => (if Is_Leap (Y) then 29 else 28),
         when others                      => 0);

   procedure Parse_Time (F : Field; Minutes : out Natural; Ok : out Boolean)
   is
      Y, Mo, D, H, Mi : Natural;
      Days            : Natural := 0;
   begin
      Minutes := 0;
      Ok      := False;
      if F.Len /= 12 or else not All_Digits (F) then
         return;
      end if;

      Y  := Dig (F.Data (1)) * 1000 + Dig (F.Data (2)) * 100
            + Dig (F.Data (3)) * 10 + Dig (F.Data (4));
      Mo := Dig (F.Data (5)) * 10 + Dig (F.Data (6));
      D  := Dig (F.Data (7)) * 10 + Dig (F.Data (8));
      H  := Dig (F.Data (9)) * 10 + Dig (F.Data (10));
      Mi := Dig (F.Data (11)) * 10 + Dig (F.Data (12));

      if Y not in 2000 .. 2100 or else Mo not in 1 .. 12
        or else D < 1 or else D > Days_In (Y, Mo)
        or else H > 23 or else Mi > 59
      then
         return;
      end if;

      for Yr in 2000 .. Y - 1 loop
         pragma Loop_Invariant (Days <= (Yr - 2000) * 366);
         Days := Days + (if Is_Leap (Yr) then 366 else 365);
      end loop;
      for M in 1 .. Mo - 1 loop
         pragma Loop_Invariant (Days <= 101 * 366 + (M - 1) * 31);
         Days := Days + Days_In (Y, M);
      end loop;
      Days := Days + (D - 1);

      Minutes := Days * 1440 + H * 60 + Mi;
      Ok      := True;
   end Parse_Time;

   ---------------------------------------------------------------------------
   --  CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) - same family as the
   --  EMVCo / PromptPay QR checksum. Modular arithmetic: cannot overflow.
   ---------------------------------------------------------------------------
   type U16 is mod 2 ** 16;

   function Crc16 (D : Val_Buf; Last : Val_Len) return U16 is
      Crc : U16 := 16#FFFF#;
   begin
      for I in 1 .. Last loop
         Crc := Crc xor (U16 (Character'Pos (D (I))) * 256);
         for B in 1 .. 8 loop
            if (Crc and 16#8000#) /= 0 then
               Crc := (Crc * 2) xor 16#1021#;
            else
               Crc := Crc * 2;
            end if;
         end loop;
      end loop;
      return Crc;
   end Crc16;

   Hex_Digits : constant String := "0123456789ABCDEF";

   function Hex4_Matches (Q : Field; Start : Positive; V : U16) return Boolean
   is
      N : Natural := Natural (V);
   begin
      if Start + 3 > Q.Len then
         return False;
      end if;
      for K in reverse 0 .. 3 loop
         if Up (Q.Data (Start + K)) /= Hex_Digits (Hex_Digits'First + N mod 16)
         then
            return False;
         end if;
         N := N / 16;
      end loop;
      return True;
   end Hex4_Matches;

   ---------------------------------------------------------------------------
   --  Mini-QR TLV parsing
   ---------------------------------------------------------------------------
   function Two_Digits (Q : Field; P : Positive) return Natural is
     (if P + 1 <= Q.Len then Dig (Q.Data (P)) * 10 + Dig (Q.Data (P + 1)) else 0);

   function Header_Ok (Q : Field; P : Positive) return Boolean is
     (P + 3 <= Q.Len
      and then Is_Dig (Q.Data (P))     and then Is_Dig (Q.Data (P + 1))
      and then Is_Dig (Q.Data (P + 2)) and then Is_Dig (Q.Data (P + 3)));

   procedure Copy_Range
     (Q : Field; First : Positive; Last : Natural; Dst : out Field)
   is
   begin
      Dst := Empty_Field;
      if Last < First or else Last > Q.Len then
         return;
      end if;
      Dst.Present := True;
      for I in First .. Last loop
         pragma Loop_Invariant (Dst.Len = I - First);
         Dst.Len := Dst.Len + 1;
         Dst.Data (Dst.Len) := Q.Data (I);
      end loop;
   end Copy_Range;

   procedure Parse_Sub
     (Q         : Field;
      First     : Positive;
      Last      : Natural;
      Bank_Code : out Field;
      Ref       : out Field;
      Ok        : out Boolean)
   is
      P : Natural := First;
      Tag, L : Natural;
   begin
      Bank_Code := Empty_Field;
      Ref       := Empty_Field;
      Ok        := False;
      while P <= Last loop
         pragma Loop_Invariant (P >= First);
         if P + 3 > Last or else not Header_Ok (Q, P) then
            return;
         end if;
         Tag := Two_Digits (Q, P);
         L   := Two_Digits (Q, P + 2);
         if P + 3 + L > Last then
            return;
         end if;
         if Tag = 1 then
            if L /= 3 then
               return;
            end if;
            Copy_Range (Q, P + 4, P + 3 + L, Bank_Code);
         elsif Tag = 2 then
            if L = 0 or else L > 40 then
               return;
            end if;
            Copy_Range (Q, P + 4, P + 3 + L, Ref);
         end if;
         P := P + 4 + L;
      end loop;
      Ok := Bank_Code.Present and then All_Digits (Bank_Code) and then Ref.Present;
   end Parse_Sub;

   procedure Parse_Qr
     (Q         : Field;
      Valid     : out Boolean;
      Crc_Ok    : out Boolean;
      Bank_Code : out Field;
      Ref       : out Field)
   is
      P         : Natural := 1;
      Tag, L    : Natural;
      Has_00    : Boolean := False;
      Has_91    : Boolean := False;
      Crc_Start : Natural := 0;
      Sub_Ok    : Boolean;
   begin
      Valid     := False;
      Crc_Ok    := False;
      Bank_Code := Empty_Field;
      Ref       := Empty_Field;

      while P <= Q.Len loop
         pragma Loop_Invariant (P >= 1);
         if not Header_Ok (Q, P) then
            return;
         end if;
         Tag := Two_Digits (Q, P);
         L   := Two_Digits (Q, P + 2);
         if P + 3 + L > Q.Len then
            return;
         end if;

         if Tag = 0 then
            if L < 8 then
               return;
            end if;
            Parse_Sub (Q, P + 4, P + 3 + L, Bank_Code, Ref, Sub_Ok);
            if not Sub_Ok then
               return;
            end if;
            Has_00 := True;
         elsif Tag = 51 then
            if L /= 2 or else Q.Data (P + 4) /= 'T' or else Q.Data (P + 5) /= 'H'
            then
               return;
            end if;
         elsif Tag = 91 then
            if L /= 4 or else P + 3 + L /= Q.Len then   --  CRC must be last
               return;
            end if;
            Crc_Start := P + 4;
            Has_91    := True;
         end if;
         P := P + 4 + L;
      end loop;

      if not (Has_00 and then Has_91) or else Crc_Start < 2 then
         return;
      end if;
      Valid  := True;
      Crc_Ok := Hex4_Matches (Q, Crc_Start, Crc16 (Q.Data, Crc_Start - 1));
   end Parse_Qr;

   ---------------------------------------------------------------------------
   --  Bank tokens -> 3-digit Bank of Thailand institution codes
   ---------------------------------------------------------------------------
   function Bank_Code_Of (F : Field) return String is
     (if    Equals (F, "BBL")   then "002"
      elsif Equals (F, "KBANK") then "004"
      elsif Equals (F, "KTB")   then "006"
      elsif Equals (F, "TTB")   then "011"
      elsif Equals (F, "SCB")   then "014"
      elsif Equals (F, "CIMB")  then "022"
      elsif Equals (F, "UOB")   then "024"
      elsif Equals (F, "BAY")   then "025"
      elsif Equals (F, "GSB")   then "030"
      elsif Equals (F, "GHB")   then "033"
      elsif Equals (F, "BAAC")  then "034"
      elsif Equals (F, "ISBT")  then "066"
      elsif Equals (F, "TISCO") then "067"
      elsif Equals (F, "KKP")   then "069"
      elsif Equals (F, "ICBC")  then "070"
      elsif Equals (F, "TCRB")  then "071"
      elsif Equals (F, "LHB")   then "073"
      else "000");

   --  OCR-tolerant comparison: O->0, I/L->1, case-insensitive; a printed
   --  ref of >= 8 chars that is contained in the QR ref (or vice versa)
   --  also matches, because some slips print a shortened reference.
   function Norm (C : Character) return Character is
     (case Up (C) is
         when 'O'       => '0',
         when 'I' | 'L' => '1',
         when others    => Up (C));

   function Contains_Norm (Big, Small : Field) return Boolean is
   begin
      if Small.Len = 0 or else Small.Len > Big.Len then
         return False;
      end if;
      for S in 1 .. Big.Len - Small.Len + 1 loop
         declare
            Match : Boolean := True;
         begin
            for J in 0 .. Small.Len - 1 loop
               if Norm (Big.Data (S + J)) /= Norm (Small.Data (1 + J)) then
                  Match := False;
                  exit;
               end if;
            end loop;
            if Match then
               return True;
            end if;
         end;
      end loop;
      return False;
   end Contains_Norm;

   function Refs_Match (A, B : Field) return Boolean is
   begin
      if A.Len = B.Len then
         return Contains_Norm (A, B);
      elsif A.Len > B.Len then
         return B.Len >= 8 and then Contains_Norm (A, B);
      else
         return A.Len >= 8 and then Contains_Norm (B, A);
      end if;
   end Refs_Match;

   function Ref_Format_Ok (F : Field) return Boolean is
   begin
      if F.Len < 8 or else F.Len > 40 then
         return False;
      end if;
      for I in 1 .. F.Len loop
         if not (Is_Dig (F.Data (I)) or else Up (F.Data (I)) in 'A' .. 'Z') then
            return False;
         end if;
      end loop;
      return True;
   end Ref_Format_Ok;

   function Field_Is (F : Field; S : String) return Boolean is
     (F.Present and then F.Len = S'Length and then Equals (F, S));

   -------------
   -- Analyze --
   -------------
   procedure Analyze (Input : Text; R : out Analysis_Result) is
      F         : Field_Set;
      Ok        : Boolean;
      Is_TM     : Boolean;
      Valid     : Boolean;
      Crc_Ok    : Boolean;
      Q_Bank    : Field;
      Q_Ref     : Field;
      Amt, Exp  : Satang;
      A_Ok      : Boolean;
      E_Ok      : Boolean;
      T, N      : Natural;
      T_Ok      : Boolean;
      N_Ok      : Boolean;
   begin
      R := Empty_Result;

      Parse (Input, F, Ok);
      if not Ok then
         Add (R, F_Sl_Bad_Input, 40);
         return;
      end if;

      Is_TM := Field_Is (F (K_Bank), "TRUEMONEY");
      if Is_TM then
         Add (R, F_Sl_Truemoney, 0);
      end if;
      Valid  := False;
      Crc_Ok := False;

      --  1. Mini-QR: structure, CRC, cross-checks
      if F (K_Qr).Present then
         Parse_Qr (F (K_Qr), Valid, Crc_Ok, Q_Bank, Q_Ref);
         if not Valid then
            Add (R, F_Sl_Qr_Malformed, 50);
         elsif not Crc_Ok then
            Add (R, F_Sl_Qr_Crc_Invalid, 70);
         else
            Add (R, F_Sl_Qr_Valid, 0);
            if not Is_TM and then F (K_Bank).Present
              and then Bank_Code_Of (F (K_Bank)) /= "000"
              and then not Equals (Q_Bank, Bank_Code_Of (F (K_Bank)))
            then
               Add (R, F_Sl_Qr_Bank_Mismatch, 60);
            end if;
            if F (K_Ref).Present and then not Refs_Match (F (K_Ref), Q_Ref) then
               Add (R, F_Sl_Ref_Mismatch, 45);
            end if;
         end if;
      else
         Add (R, F_Sl_No_Qr, (if Is_TM then 10 else 30));
      end if;

      --  Bank could not be identified from the text AND no valid QR proves it
      if not Is_TM and then not (Valid and then Crc_Ok)
        and then (not F (K_Bank).Present
                  or else Bank_Code_Of (F (K_Bank)) = "000")
      then
         Add (R, F_Sl_Bank_Unknown, 15);
      end if;

      --  2. Printed reference format
      if F (K_Ref).Present and then not Ref_Format_Ok (F (K_Ref)) then
         Add (R, F_Sl_Ref_Format, 15);
      end if;

      --  3. Amount
      if not F (K_Amount).Present then
         Add (R, F_Sl_Amount_Missing, 20);
      else
         Parse_Amount (F (K_Amount), Amt, A_Ok);
         if not A_Ok or else Amt = 0 then
            Add (R, F_Sl_Amount_Invalid, 30);
         elsif F (K_Expected).Present then
            Parse_Amount (F (K_Expected), Exp, E_Ok);
            if E_Ok and then Exp /= Amt then
               Add (R, F_Sl_Amount_Mismatch, 50);
            end if;
         end if;
      end if;

      --  4. Time
      if not F (K_Time).Present then
         Add (R, F_Sl_Time_Missing, 15);
      else
         Parse_Time (F (K_Time), T, T_Ok);
         if not T_Ok then
            Add (R, F_Sl_Time_Invalid, 40);
         elsif F (K_Now).Present then
            Parse_Time (F (K_Now), N, N_Ok);
            if N_Ok then
               if T > N + 5 then
                  Add (R, F_Sl_Future_Time, 70);      --  dated in the future
               elsif N > T and then N - T > 3 * 1440 then
                  Add (R, F_Sl_Old_Slip, 25);         --  > 3 days old
               end if;
            end if;
         end if;
      end if;

      --  5. Image-forensics facts from the vision layer
      if Field_Is (F (K_Edited), "1") then
         Add (R, F_Sl_Edited_Software, 50);
      end if;
      if Field_Is (F (K_Inconsistent), "1") then
         Add (R, F_Sl_Text_Inconsistent, 25);
      end if;
      if Field_Is (F (K_Dup), "1") then
         Add (R, F_Sl_Duplicate, 70);
      end if;
      if All_Digits (F (K_Ocr_Conf)) then
         declare
            C : Natural := 0;
         begin
            for I in 1 .. F (K_Ocr_Conf).Len loop
               C := C * 10 + Dig (F (K_Ocr_Conf).Data (I));   --  <= 999
            end loop;
            if C < 50 then
               Add (R, F_Sl_Low_Ocr, 10);
            end if;
         end;
      end if;
   end Analyze;

end TCS_Slip;
