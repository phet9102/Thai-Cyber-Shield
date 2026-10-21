--  ===========================================================================
--  Package : TCS_Slip
--  Purpose : Multi-bank & TrueMoney transfer-slip verifier.
--
--  The Python vision layer (OCR + QR decoder + image forensics) extracts
--  FACTS from the screenshot and sends them here as strict ASCII lines:
--
--      bank=KBANK          one token from a closed set (or UNKNOWN)
--      ref=016294123456ABC transaction reference read by OCR
--      amount=1500.00      amount read by OCR (digits, optional .dd)
--      expected=1500.00    amount the user expected to receive (optional)
--      time=202610212305   slip date-time, Gregorian yyyymmddhhmm
--      now=202610212310    server clock, same format
--      qr=00410006000001...raw payload of the slip-verification mini QR
--      edited=1            editing software found in image metadata
--      inconsistent=1      text-line height/stroke inconsistency detected
--      dup=1               this transaction ref was already submitted before
--      ocr_conf=78         mean OCR confidence 0..100
--
--  The engine NEVER trusts these facts blindly: every value is re-parsed
--  with bounded, typed parsers. Its own deterministic checks are:
--    * Mini-QR TLV structure (tag 00 -> sub-tags 00 API id / 01 bank code /
--      02 transaction ref, tag 51 = "TH", tag 91 = CRC) and the CRC-16/
--      CCITT-FALSE checksum, computed here - a forged or retyped QR fails.
--    * QR bank code vs bank detected on the slip, QR ref vs printed ref.
--    * Calendar-correct time parsing, slips dated in the future, stale slips.
--    * Amount parsing in satang (no floating point) and expected-amount match.
--
--  Limitation (documented to users): a valid QR proves the slip *format* is
--  genuine; only the bank (or a bank-connected slip-verification service)
--  can prove the money actually arrived.
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_Slip with SPARK_Mode => On is

   procedure Analyze (Input : Text; R : out Analysis_Result)
     with Global => null,
          Pre    => Input.Len <= Max_Slip_CP,
          Post   => R.Count <= Max_Findings;

end TCS_Slip;
