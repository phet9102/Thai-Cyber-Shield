--  ===========================================================================
--  Package : TCS_SMS
--  Purpose : Advanced SMS scam & keyword heuristic parser (Thai + English).
--            - Anti-evasion: matching runs on a normalised "compact" view so
--              "โ.อ.น เ-งิ-น", Thai digits and fullwidth letters still match.
--            - Category scoring with diminishing returns + combination rules
--              (authority + link, urgency + link, lure + contact channel).
--            - Malicious payload / format-string telemetry: the engine never
--              interprets input as a format or markup (Ada has no printf),
--              these patterns are only *reported*.
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_SMS with SPARK_Mode => On is

   procedure Analyze (Input : Text; R : out Analysis_Result)
     with Global => null,
          Pre    => Input.Len <= Max_SMS_CP;

end TCS_SMS;
