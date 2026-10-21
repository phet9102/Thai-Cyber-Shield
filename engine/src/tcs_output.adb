with Ada.Text_IO;

package body TCS_Output with SPARK_Mode => Off is

   use Ada.Text_IO;

   Engine_Id : constant String := "tcs-ada/1.0";

   function Nat_Img (N : Natural) return String is
      S : constant String := Natural'Image (N);   --  leading space
   begin
      return S (S'First + 1 .. S'Last);
   end Nat_Img;

   function Finding_Img (F : Finding_Code) return String is
      S : constant String := Finding_Code'Image (F);   --  e.g. "F_URL_APK"
   begin
      if S'Length > 2 and then S (S'First .. S'First + 1) = "F_" then
         return S (S'First + 2 .. S'Last);
      end if;
      return S;
   end Finding_Img;

   --  Strict allow-list: lower-case ASCII letters, digits, '.', '-', ':'
   function Host_Is_Safe (H : Text) return Boolean is
   begin
      if H.Len = 0 then
         return False;
      end if;
      for I in 1 .. H.Len loop
         declare
            P : constant Natural := Wide_Wide_Character'Pos (H.Data (I));
         begin
            if not (P in Character'Pos ('a') .. Character'Pos ('z')
                    or else P in Character'Pos ('0') .. Character'Pos ('9')
                    or else P = Character'Pos ('.')
                    or else P = Character'Pos ('-')
                    or else P = Character'Pos (':'))
            then
               return False;
            end if;
         end;
      end loop;
      return True;
   end Host_Is_Safe;

   procedure Emit_Result
     (Mode : String;
      R    : Analysis_Result;
      Host : Text := Empty_Text) is
   begin
      Put ("{""ok"":true,""engine"":""" & Engine_Id & """,""mode"":""");
      Put (Mode);
      Put (""",""score"":");
      Put (Nat_Img (Natural (R.Score)));
      Put (",""level"":""");
      Put (Risk_Level'Image (Level_Of (R.Score)));
      Put (""",""findings"":[");
      for I in 1 .. R.Count loop
         if I > 1 then
            Put (",");
         end if;
         Put ("""" & Finding_Img (R.Findings (I)) & """");
      end loop;
      Put ("]");

      if Host_Is_Safe (Host) then
         Put (",""host"":""");
         for I in 1 .. Host.Len loop
            --  Safe: Host_Is_Safe guarantees every code point is ASCII
            Put (Character'Val (Wide_Wide_Character'Pos (Host.Data (I))));
         end loop;
         Put ("""");
      else
         Put (",""host"":null");
      end if;

      Put_Line ("}");
      Flush;
   end Emit_Result;

   procedure Emit_Error (Code : String) is
   begin
      Put_Line ("{""ok"":false,""engine"":""" & Engine_Id
                & """,""error"":""" & Code & """}");
      Flush;
   exception
      when others =>
         null;   --  stdout closed by parent: nothing more we can do safely
   end Emit_Error;

end TCS_Output;
