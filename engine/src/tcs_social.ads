--  ===========================================================================
--  Package : TCS_Social
--  Purpose : Facebook link / post analyzer and e-mail address analyzer.
--
--  Facebook links: the full TCS_URL analysis runs first (homoglyphs,
--  punycode, userinfo, suspicious TLD, brand impersonation...). On top of it
--  Facebook-specific structure is checked:
--    * genuine Facebook family host (facebook.com, fb.com, fb.me, fb.watch,
--      messenger.com) with strict suffix matching
--    * numeric profile IDs (profile.php?id=...) and the very-recent ID range
--      (weak signal: new accounts are common for scam sellers)
--    * /share/ links (hide the real target), l.php link-shim redirects
--    * look-alike hosts (faceb00k, fb-support, meta-business...) and the
--      classic "page violation / copyright appeal / checkpoint" phishing paths
--
--  E-mail: strict RFC-5321-style syntax, free / disposable providers,
--  bank or authority names used on free mailboxes, digit-heavy local parts,
--  and the domain itself goes through TCS_URL host analysis.
--
--  Nothing here contacts Facebook or any external service: it is pure
--  structural analysis of the string the user supplied.
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_Social with SPARK_Mode => On is

   procedure Analyze_Facebook
     (Input : Text; R : out Analysis_Result; Host : out Text)
     with Global => null,
          Pre    => Input.Len <= Max_URL_CP,
          Post   => R.Count <= Max_Findings and then Host.Len <= 253;

   procedure Analyze_Email
     (Input : Text; R : out Analysis_Result; Host : out Text)
     with Global => null,
          Pre    => Input.Len <= Max_Email_CP,
          Post   => R.Count <= Max_Findings and then Host.Len <= 253;

end TCS_Social;
