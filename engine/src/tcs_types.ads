--  ===========================================================================
--  Thai Cyber Shield - Secure Core Engine
--  Package : TCS_Types
--  Purpose : Every bounded type used by the engine. All buffers are fixed-size
--            arrays with constrained index subtypes, so an out-of-range write is
--            either rejected statically by GNATprove or raises Constraint_Error
--            (never silent memory corruption). No access types, no heap.
--  ===========================================================================

package TCS_Types with SPARK_Mode => On is

   ---------------------------------------------------------------------------
   --  Raw byte input (as received on stdin)
   ---------------------------------------------------------------------------
   type Byte is mod 2 ** 8;

   Max_Raw_Bytes : constant := 8_192;          --  hard ceiling on stdin bytes

   subtype Raw_Length is Natural  range 0 .. Max_Raw_Bytes;
   subtype Raw_Index  is Positive range 1 .. Max_Raw_Bytes;
   type Raw_Buffer is array (Raw_Index) of Byte;

   ---------------------------------------------------------------------------
   --  Decoded Unicode text (UTF-32 code points, validated)
   ---------------------------------------------------------------------------
   Max_Code_Points : constant := 2_048;

   --  Per-analyzer limits, all <= Max_Code_Points
   Max_SMS_CP   : constant := 1_000;
   Max_URL_CP   : constant := 2_048;
   Max_Phone_CP : constant := 32;

   subtype CP_Length is Natural  range 0 .. Max_Code_Points;
   subtype CP_Index  is Positive range 1 .. Max_Code_Points;
   type CP_Buffer is array (CP_Index) of Wide_Wide_Character;

   type Text is record
      Data : CP_Buffer := (others => ' ');
      Len  : CP_Length := 0;
   end record;

   Empty_Text : constant Text := (Data => (others => ' '), Len => 0);

   ---------------------------------------------------------------------------
   --  Risk scoring
   ---------------------------------------------------------------------------
   type Risk_Score is range 0 .. 100;
   subtype Weight is Natural range 0 .. 100;

   type Risk_Level is (Safe, Low, Medium, High, Critical);

   function Level_Of (S : Risk_Score) return Risk_Level is
     (if    S >= 80 then Critical
      elsif S >= 60 then High
      elsif S >= 35 then Medium
      elsif S >= 15 then Low
      else  Safe);

   ---------------------------------------------------------------------------
   --  Finding codes. The JSON output uses 'Image without the "F_" prefix,
   --  so the set of strings the engine can ever emit is closed and known.
   ---------------------------------------------------------------------------
   type Finding_Code is
     (F_None,
      --  Generic input-level indicators
      F_Invisible_Chars,
      F_Bidi_Override,
      F_Payload_Pattern,
      F_Format_String,
      F_Evasion_Spacing,
      --  SMS heuristics
      F_Sms_Urgency,
      F_Sms_Money_Lure,
      F_Sms_Gambling,
      F_Sms_Loan,
      F_Sms_Investment,
      F_Sms_Authority,
      F_Sms_Bank_Brand,
      F_Sms_Parcel,
      F_Sms_Credential_Request,
      F_Sms_Transfer_Request,
      F_Sms_Contact_Channel,
      F_Sms_Contains_Url,
      F_Sms_Contains_Shortener,
      F_Sms_Contains_Apk,
      F_Sms_Contains_Phone,
      F_Sms_Mixed_Script,
      F_Combo_Authority_Link,
      F_Combo_Urgency_Link,
      F_Combo_Lure_Contact,
      --  URL heuristics
      F_Url_Dangerous_Scheme,
      F_Url_No_Tls,
      F_Url_Userinfo,
      F_Url_Ip_Host,
      F_Url_Obfuscated_Ip,
      F_Url_Nonstd_Port,
      F_Url_Punycode,
      F_Url_Unicode_Host,
      F_Url_Homoglyph,
      F_Url_Deep_Subdomain,
      F_Url_Many_Hyphens,
      F_Url_Suspicious_Tld,
      F_Url_Shortener,
      F_Url_Brand_Impersonation,
      F_Url_Gov_Lookalike,
      F_Url_Apk,
      F_Url_Phish_Path,
      F_Url_Encoded_Evasion,
      F_Url_Open_Redirect,
      F_Url_Excessive_Length,
      F_Url_Malformed,
      F_Url_Backslash_Trick,
      F_Url_Trailing_Dot,
      F_Url_Official_Domain,
      --  Phone heuristics
      F_Ph_Unassigned_Cc,
      F_Ph_Spoof_No_Plus,
      F_Ph_High_Risk_Region,
      F_Ph_Satellite,
      F_Ph_International,
      F_Ph_Premium_Rate,
      F_Ph_Malformed_Trunk,
      F_Ph_Invalid_Length,
      F_Ph_Abnormal_Pattern,
      F_Ph_Service_Shortcode,
      F_Ph_Thai_Mobile,
      F_Ph_Thai_Landline,
      F_Ph_Invalid_Format);

   Max_Findings : constant := 24;
   subtype Finding_Count is Natural range 0 .. Max_Findings;
   subtype Finding_Index is Positive range 1 .. Max_Findings;
   type Finding_Array is array (Finding_Index) of Finding_Code;

   type Analysis_Result is record
      Score    : Risk_Score    := 0;
      Findings : Finding_Array := (others => F_None);
      Count    : Finding_Count := 0;
   end record;

   Empty_Result : constant Analysis_Result :=
     (Score => 0, Findings => (others => F_None), Count => 0);

   function Has (R : Analysis_Result; Code : Finding_Code) return Boolean
     with Global => null;

   --  Record a finding once and add its weight with saturation at 100.
   --  Cannot overflow: Natural (Score) + W <= 200.
   procedure Add (R : in out Analysis_Result; Code : Finding_Code; W : Weight)
     with Global => null,
          Post   => R.Score >= R.Score'Old and then R.Count >= R.Count'Old;

   --  Clamp score down (used only for verified official domains).
   procedure Cap (R : in out Analysis_Result; Max : Risk_Score)
     with Global => null,
          Post   => R.Score <= Max;

end TCS_Types;
