--  ===========================================================================
--  Package : TCS_Output
--  Purpose : The ONLY place that writes to stdout. Emits exactly one line of
--            JSON built from a closed vocabulary (enum images, integers,
--            and a host string that passes a strict ASCII allow-list).
--            User input is never echoed, so the JSON cannot be broken out of
--            and nothing can be interpreted as a format specifier.
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_Output with SPARK_Mode => Off is

   procedure Emit_Result
     (Mode : String;
      R    : Analysis_Result;
      Host : Text := Empty_Text);

   procedure Emit_Error (Code : String);
   --  Code must be a compile-time constant from TCS_Main (A-Z and '_').

end TCS_Output;
