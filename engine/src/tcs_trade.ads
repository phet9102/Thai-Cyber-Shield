--  ===========================================================================
--  Package : TCS_Trade
--  Purpose : Advanced chat & item-trade fraud heuristic parser.
--            Input is a buy/sell conversation (typed or OCR'd from a
--            screenshot) about games, digital items or physical goods.
--            It scores *fraud linguistic patterns* that repeatedly appear in
--            Thai trading scams:
--              * pay-first + refusal of a neutral middleman ("ไม่รับกลาง")
--              * FAKE ESCROW - "my own middleman / admin middleman / escrow
--                site" (the scammer controls the so-called neutral party)
--              * urgency traps ("มีคนรอ", "เหลือชิ้นสุดท้าย")
--              * credential harvesting (game password, OTP, bound e-mail)
--              * off-platform moves, third-party bank accounts,
--                over-payment refund, fee traps, TrueMoney angpao payment,
--                fake-slip excuses ("สลิปไม่เข้า"), threats
--            Same anti-evasion views as TCS_SMS (compact view, Thai digits).
--
--  SPARK contract: Pre bounds the input; Post guarantees the score range
--  and that every reported finding index is within the result array.
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_Trade with SPARK_Mode => On is

   procedure Analyze (Input : Text; R : out Analysis_Result)
     with Global => null,
          Pre    => Input.Len <= Max_Trade_CP,
          Post   => R.Count <= Max_Findings
                      and then Natural (R.Score) <= 100;

end TCS_Trade;
