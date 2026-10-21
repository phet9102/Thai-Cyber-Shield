--  ===========================================================================
--  Package : TCS_URL
--  Purpose : Deep URL structural & heuristic analyzer.
--            Hand-written single-pass parser (no regex => no ReDoS) that
--            splits scheme / userinfo / host / port / path and scores:
--              * dangerous schemes (javascript:, data:, vbscript:, file:)
--              * userinfo "@" deception  (https://ktb.co.th@evil.example)
--              * IP literal hosts, decimal/hex/octal obfuscated IPs
--              * Punycode (xn--), raw Unicode hosts, mixed-script homoglyphs,
--                ideographic full-stop dot spoofing
--              * suspicious TLDs, URL shorteners, deep subdomain chains
--              * Thai bank / government / courier brand impersonation with a
--                strict suffix-match allow-list of official domains
--              * .apk delivery, phishing path words, open-redirect params,
--                percent-encoding evasion, backslash and trailing-dot tricks
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_URL with SPARK_Mode => On is

   Max_Host_CP : constant := 253;

   --  Host is the extracted, lower-cased host. The caller only emits it if
   --  it consists solely of [a-z0-9.-:] characters.
   procedure Analyze (Input : Text; R : out Analysis_Result; Host : out Text)
     with Global => null,
          Pre    => Input.Len <= Max_URL_CP,
          Post   => Host.Len <= Max_Host_CP;

end TCS_URL;
