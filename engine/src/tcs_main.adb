--  ===========================================================================
--  Thai Cyber Shield - Secure Core Engine : entry point
--
--  Protocol (designed to be called by the API with an argv array, no shell):
--
--      tcs_engine sms|url|phone   < untrusted UTF-8 bytes on stdin
--
--    * argv carries ONLY the mode, checked against a closed set. User data
--      never appears in argv (no option injection, no /proc/<pid>/cmdline
--      leak, no ARG_MAX issues).
--    * stdin is read in fixed chunks into a bounded buffer; anything beyond
--      Max_Raw_Bytes is rejected, not truncated.
--    * stdout: exactly one JSON line. stderr: never used.
--
--  Exit codes: 0 analysed | 2 input rejected | 3 internal fault | 64 usage
--
--  Fault tolerance: all analysis code is SPARK (no exceptions possible once
--  proved with GNATprove). This non-SPARK shell still wraps everything in a
--  last-resort handler (Constraint_Error, Storage_Error from -fstack-check,
--  Assertion_Error from -gnata contracts, I/O errors) so the process ALWAYS
--  terminates with a well-formed JSON line and a defined exit code.
--  ===========================================================================

with Ada.Command_Line;
with Ada.Streams;
with Ada.Text_IO;
with Ada.Text_IO.Text_Streams;

with TCS_Types;  use TCS_Types;
with TCS_UTF8;   use TCS_UTF8;
with TCS_SMS;
with TCS_URL;
with TCS_Phone;
with TCS_Output;

procedure TCS_Main with SPARK_Mode => Off is

   package CL renames Ada.Command_Line;

   type Mode_Kind is (Mode_SMS, Mode_URL, Mode_Phone);

   Exit_Ok       : constant CL.Exit_Status := 0;
   Exit_Rejected : constant CL.Exit_Status := 2;
   Exit_Fault    : constant CL.Exit_Status := 3;
   Exit_Usage    : constant CL.Exit_Status := 64;

   --  Library-level-sized buffers live in this frame (~8 KB + 3 x 8 KB);
   --  no heap allocation anywhere in the engine.
   Raw      : Raw_Buffer := (others => 0);
   Raw_Len  : Raw_Length := 0;
   Too_Long : Boolean    := False;

   Mode     : Mode_Kind;
   Decoded  : Text;
   Status   : Decode_Status;
   Result   : Analysis_Result;
   Host     : Text;

   ---------------------------------------------------------------------------
   procedure Read_Stdin
     (Buf : in out Raw_Buffer; Len : out Raw_Length; Overflow : out Boolean)
   is
      use Ada.Streams;
      S     : constant Ada.Text_IO.Text_Streams.Stream_Access :=
                Ada.Text_IO.Text_Streams.Stream (Ada.Text_IO.Standard_Input);
      Chunk : Stream_Element_Array (1 .. 1_024);
      Last  : Stream_Element_Offset;
   begin
      Len      := 0;
      Overflow := False;
      loop
         Ada.Streams.Read (S.all, Chunk, Last);
         exit when Last < Chunk'First;                    --  EOF
         for I in Chunk'First .. Last loop
            if Len = Max_Raw_Bytes then
               Overflow := True;                          --  reject, never truncate
               return;
            end if;
            Len := Len + 1;
            Buf (Len) := Byte (Chunk (I));
         end loop;
      end loop;
   end Read_Stdin;

   ---------------------------------------------------------------------------
   function Mode_Name (M : Mode_Kind) return String is
     (case M is
         when Mode_SMS   => "sms",
         when Mode_URL   => "url",
         when Mode_Phone => "phone");

   function Max_CP_For (M : Mode_Kind) return CP_Length is
     (case M is
         when Mode_SMS   => Max_SMS_CP,
         when Mode_URL   => Max_URL_CP,
         when Mode_Phone => Max_Phone_CP);

   procedure Reject (Code : String) is
   begin
      TCS_Output.Emit_Error (Code);
      CL.Set_Exit_Status (Exit_Rejected);
   end Reject;

begin
   CL.Set_Exit_Status (Exit_Fault);   --  pessimistic default

   ---------------------------------------------------------------------------
   --  1. argv: exactly one argument from a closed set
   ---------------------------------------------------------------------------
   if CL.Argument_Count /= 1 then
      TCS_Output.Emit_Error ("USAGE");
      CL.Set_Exit_Status (Exit_Usage);
      return;
   end if;

   declare
      A : constant String := CL.Argument (1);
   begin
      if A = "sms" then
         Mode := Mode_SMS;
      elsif A = "url" then
         Mode := Mode_URL;
      elsif A = "phone" then
         Mode := Mode_Phone;
      else
         TCS_Output.Emit_Error ("USAGE");
         CL.Set_Exit_Status (Exit_Usage);
         return;
      end if;
   end;

   ---------------------------------------------------------------------------
   --  2. Bounded read of untrusted bytes
   ---------------------------------------------------------------------------
   Read_Stdin (Raw, Raw_Len, Too_Long);
   if Too_Long then
      Reject ("INPUT_TOO_LONG");
      return;
   end if;

   ---------------------------------------------------------------------------
   --  3. Strict UTF-8 validation with per-mode code-point limit
   ---------------------------------------------------------------------------
   Decode (Raw, Raw_Len, Max_CP_For (Mode), Decoded, Status);

   case Status is
      when Decode_Ok                => null;
      when Decode_Empty             => Reject ("INPUT_EMPTY");             return;
      when Decode_Invalid_UTF8      => Reject ("INPUT_INVALID_UTF8");      return;
      when Decode_Forbidden_Control => Reject ("INPUT_FORBIDDEN_CONTROL"); return;
      when Decode_Too_Long          => Reject ("INPUT_TOO_LONG");          return;
   end case;

   --  Wipe the raw copy as soon as it is no longer needed (data minimisation)
   Raw := (others => 0);

   ---------------------------------------------------------------------------
   --  4. Analyse (SPARK code) and emit
   ---------------------------------------------------------------------------
   case Mode is
      when Mode_SMS =>
         TCS_SMS.Analyze (Decoded, Result);
         TCS_Output.Emit_Result (Mode_Name (Mode), Result);
      when Mode_URL =>
         TCS_URL.Analyze (Decoded, Result, Host);
         TCS_Output.Emit_Result (Mode_Name (Mode), Result, Host);
      when Mode_Phone =>
         TCS_Phone.Analyze (Decoded, Result);
         TCS_Output.Emit_Result (Mode_Name (Mode), Result);
   end case;

   CL.Set_Exit_Status (Exit_Ok);

exception
   --  Last line of defence: never crash with a stack trace / partial output.
   when others =>
      begin
         TCS_Output.Emit_Error ("ENGINE_FAULT");
      exception
         when others => null;
      end;
      CL.Set_Exit_Status (Exit_Fault);
end TCS_Main;
