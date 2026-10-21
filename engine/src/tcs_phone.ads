--  ===========================================================================
--  Package : TCS_Phone
--  Purpose : High-speed international phone pattern matcher.
--            O(n) single pass over at most 32 code points, zero allocation.
--            Detects:
--              * unassigned ITU country codes +693..+699 (the "+697 / +698"
--                caller-ID spoofing used by Thai call-centre gangs)
--              * the same digits displayed WITHOUT '+' (697xxxxxxxx)
--              * +66 followed by trunk '0' (+66 0xx...) - a spoofing artefact
--              * high-risk origin regions, satellite/international networks
--              * premium-rate 1900, invalid Thai lengths, digit-run anomalies
--            Thai digits (๐-๙) and fullwidth digits are normalised first.
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_Phone with SPARK_Mode => On is

   procedure Analyze (Input : Text; R : out Analysis_Result)
     with Global => null,
          Pre    => Input.Len <= Max_Phone_CP;

end TCS_Phone;
