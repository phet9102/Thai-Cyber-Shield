--  ===========================================================================
--  Package : TCS_UTF8
--  Purpose : Strict UTF-8 -> UTF-32 decoder (RFC 3629).
--            Rejects: overlong forms, surrogates (U+D800..DFFF), code points
--            above U+10FFFF, truncated sequences, stray continuation bytes,
--            NUL / C0 controls (except TAB, LF, CR), DEL and C1 controls.
--            This is the single entry point for untrusted bytes: every
--            analyzer only ever sees a validated Text value.
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_UTF8 with SPARK_Mode => On is

   type Decode_Status is
     (Decode_Ok,
      Decode_Empty,
      Decode_Invalid_UTF8,
      Decode_Forbidden_Control,
      Decode_Too_Long);

   procedure Decode
     (Raw      : Raw_Buffer;
      Raw_Len  : Raw_Length;
      Max_CP   : CP_Length;
      Result   : out Text;
      Status   : out Decode_Status)
     with Global => null,
          Post   => Result.Len <= Max_CP
                      and then (if Status /= Decode_Ok then Result.Len = 0);

end TCS_UTF8;
