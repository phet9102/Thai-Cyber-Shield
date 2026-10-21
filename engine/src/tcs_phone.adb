with TCS_Text; use TCS_Text;

package body TCS_Phone with SPARK_Mode => On is

   subtype Digit_Count is Natural  range 0 .. Max_Phone_CP;
   subtype Digit_Index is Positive range 1 .. Max_Phone_CP;
   type Digit_Buffer is array (Digit_Index) of Character;

   procedure Analyze (Input : Text; R : out Analysis_Result) is
      D    : Digit_Buffer := (others => '0');
      N    : Digit_Count  := 0;
      Plus : Boolean      := False;
      Intl : Boolean      := False;
      O    : Positive     := 1;      --  first digit of the country code

      ---------------------------------------------------------------
      --  D(P ..) starts with S ?  (bounds-checked, never reads past N)
      ---------------------------------------------------------------
      function Digits_At (P : Positive; S : String) return Boolean is
      begin
         if S'Length = 0 or else P > N or else S'Length > N - P + 1 then
            return False;
         end if;
         for J in 0 .. S'Length - 1 loop
            if D (P + J) /= S (S'First + J) then
               return False;
            end if;
         end loop;
         return True;
      end Digits_At;

      ---------------------------------------------------------------
      --  Thai national significant number starting at index F
      ---------------------------------------------------------------
      procedure Classify_Thai_NSN (F : Positive) is
         Len : Natural;
      begin
         if F > N then
            Add (R, F_Ph_Invalid_Length, 20);
            return;
         end if;
         Len := N - F + 1;
         if Len = 9 and then D (F) in '6' | '8' | '9' then
            Add (R, F_Ph_Thai_Mobile, 0);
         elsif Len = 8 and then D (F) in '2' .. '7' then
            Add (R, F_Ph_Thai_Landline, 0);
         else
            Add (R, F_Ph_Invalid_Length, 20);
         end if;
      end Classify_Thai_NSN;

      ---------------------------------------------------------------
      --  Longest run of one repeated digit
      ---------------------------------------------------------------
      function Max_Repeat return Natural is
         Best : Natural := 0;
         Run  : Natural := 0;
      begin
         for I in 1 .. N loop
            pragma Loop_Invariant (Run < I and then Best < I);
            if I > 1 and then D (I) = D (I - 1) then
               Run := Run + 1;
            else
               Run := 1;
            end if;
            Best := Natural'Max (Best, Run);
         end loop;
         return Best;
      end Max_Repeat;

   begin
      R := Empty_Result;

      ------------------------------------------------------------------
      --  1. Normalise + whitelist characters
      ------------------------------------------------------------------
      for I in 1 .. Input.Len loop
         pragma Loop_Invariant (N < I);
         declare
            Raw : constant Wide_Wide_Character := Input.Data (I);
            C   : constant Wide_Wide_Character := Normalize_Char (Raw);
         begin
            if Is_Zero_Width (Raw) or else Is_Bidi_Control (Raw) then
               Add (R, F_Invisible_Chars, 30);
               Add (R, F_Ph_Invalid_Format, 40);
               return;
            elsif Is_Digit (C) then
               N := N + 1;
               D (N) := Character'Val (Wide_Wide_Character'Pos (C));
            elsif C = '+' then
               if N = 0 and then not Plus then
                  Plus := True;
               else
                  Add (R, F_Ph_Invalid_Format, 40);    --  '+' in the middle
                  return;
               end if;
            elsif Is_Space (C) or else C = '-' or else C = '(' or else C = ')'
              or else C = '.' or else C = '/'
            then
               null;                                  --  harmless formatting
            else
               Add (R, F_Ph_Invalid_Format, 40);       --  letters, symbols
               return;
            end if;
         end;
      end loop;

      if N < 3 then
         Add (R, F_Ph_Invalid_Format, 40);
         return;
      end if;

      if Max_Repeat >= 7 then
         Add (R, F_Ph_Abnormal_Pattern, 15);
      end if;

      ------------------------------------------------------------------
      --  2. Determine numbering plan
      ------------------------------------------------------------------
      if Plus then
         Intl := True;
         O    := 1;
      elsif Digits_At (1, "00") then
         Intl := True;
         O    := 3;
      elsif D (1) = '0' then
         Classify_Thai_NSN (2);                       --  domestic 0xxxxxxxxx
      elsif Digits_At (1, "1900") then
         Add (R, F_Ph_Premium_Rate, 30);
         if N /= 10 then
            Add (R, F_Ph_Invalid_Length, 10);
         end if;
      elsif N = 11 and then Digits_At (1, "66") then
         Intl := True;                                --  "66812345678"
         O    := 1;
      elsif N >= 9 and then Digits_At (1, "69")
        and then D (3) in '3' .. '9'
      then
         Add (R, F_Ph_Spoof_No_Plus, 20);             --  "697xxxxxxx"
         Add (R, F_Ph_Unassigned_Cc, 85);
      elsif N in 4 .. 5 and then D (1) = '1' then
         Add (R, F_Ph_Service_Shortcode, 0);
      else
         Add (R, F_Ph_Invalid_Length, 20);
      end if;

      ------------------------------------------------------------------
      --  3. International analysis
      ------------------------------------------------------------------
      if Intl then
         if O > N then
            Add (R, F_Ph_Invalid_Format, 40);
            return;
         end if;

         if Digits_At (O, "66") then
            if O + 2 > N then
               Add (R, F_Ph_Invalid_Length, 20);
            elsif D (O + 2) = '0' then
               Add (R, F_Ph_Malformed_Trunk, 30);     --  +66 0812...
               Classify_Thai_NSN (O + 3);
            else
               Classify_Thai_NSN (O + 2);
            end if;

         elsif Digits_At (O, "69") and then O + 2 <= N
           and then D (O + 2) in '3' .. '9'
         then
            Add (R, F_Ph_Unassigned_Cc, 85);          --  +693 .. +699

         elsif D (O) = '0' then
            Add (R, F_Ph_Invalid_Format, 40);         --  CC never starts 0

         elsif Digits_At (O, "855") or else Digits_At (O, "856")
           or else Digits_At (O, "95")
         then
            Add (R, F_Ph_High_Risk_Region, 25);
            Add (R, F_Ph_International, 20);

         elsif Digits_At (O, "881") or else Digits_At (O, "882")
           or else Digits_At (O, "883")
         then
            Add (R, F_Ph_Satellite, 40);
            Add (R, F_Ph_International, 20);

         else
            Add (R, F_Ph_International, 20);
         end if;

         --  ITU-T E.164: at most 15 digits including the country code
         if N - O + 1 > 15 then
            Add (R, F_Ph_Invalid_Length, 25);
         elsif N - O + 1 < 7 then
            Add (R, F_Ph_Invalid_Length, 20);
         end if;
      end if;
   end Analyze;

end TCS_Phone;
