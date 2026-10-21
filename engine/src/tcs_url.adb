pragma Wide_Character_Encoding (UTF8);

with TCS_Text; use TCS_Text;

package body TCS_URL with SPARK_Mode => On is

   ---------------------------------------------------------------------------
   --  Tables
   ---------------------------------------------------------------------------
   Dangerous_Schemes : constant Keyword_List :=
     (KW ("javascript:"), KW ("data:"), KW ("vbscript:"), KW ("file:"),
      KW ("blob:"), KW ("intent:"), KW ("jar:"));

   Https_Prefix  : constant Keyword := KW ("https://");
   Http_Prefix   : constant Keyword := KW ("http://");
   Rel_Prefix    : constant Keyword := KW ("//");
   Scheme_Sep    : constant Keyword := KW ("://");
   Xn_Prefix     : constant Keyword := KW ("xn--");
   Xn_Label      : constant Keyword := KW (".xn--");
   Apk_Ext       : constant Keyword := KW (".apk");
   Double_Encode : constant Keyword := KW ("%25");
   Hex_Prefix    : constant Keyword := KW ("0x");
   Gov_Th        : constant Keyword := KW ("go.th");
   Port_80       : constant Keyword := KW ("80");
   Port_443      : constant Keyword := KW ("443");

   Suspicious_TLDs : constant Keyword_List :=
     (KW ("top"), KW ("xyz"), KW ("icu"), KW ("tk"), KW ("ml"), KW ("ga"),
      KW ("cf"), KW ("gq"), KW ("buzz"), KW ("cyou"), KW ("rest"),
      KW ("sbs"), KW ("cfd"), KW ("bond"), KW ("click"), KW ("link"),
      KW ("work"), KW ("fit"), KW ("loan"), KW ("win"), KW ("bid"),
      KW ("vip"), KW ("monster"), KW ("quest"), KW ("zip"), KW ("mov"),
      KW ("shop"), KW ("online"), KW ("site"), KW ("live"), KW ("lol"),
      KW ("cc"));

   Shortener_Hosts : constant Keyword_List :=
     (KW ("bit.ly"), KW ("tinyurl.com"), KW ("cutt.ly"), KW ("shorturl.at"),
      KW ("shorturl.asia"), KW ("t.ly"), KW ("rb.gy"), KW ("is.gd"),
      KW ("s.id"), KW ("rebrand.ly"), KW ("goo.gl"), KW ("ow.ly"),
      KW ("t.co"), KW ("tny.im"), KW ("lin.ee"));

   --  Allow-list of official domains (exact or proper subdomain match only).
   --  Keep this list under change control; it is a trust anchor.
   Official_Domains : constant Keyword_List :=
     (KW ("go.th"), KW ("bot.or.th"), KW ("kasikornbank.com"),
      KW ("scb.co.th"), KW ("scbx.com"), KW ("krungthai.com"),
      KW ("bangkokbank.com"), KW ("krungsri.com"), KW ("ttbbank.com"),
      KW ("gsb.or.th"), KW ("baac.or.th"), KW ("ghbank.co.th"),
      KW ("thailandpost.co.th"), KW ("kerryexpress.com"),
      KW ("flashexpress.co.th"), KW ("flashexpress.com"),
      KW ("lazada.co.th"), KW ("shopee.co.th"), KW ("line.me"),
      KW ("facebook.com"), KW ("egat.co.th"), KW ("pea.co.th"),
      KW ("mea.or.th"), KW ("set.or.th"));

   Brand_Tokens : constant Keyword_List :=
     (KW ("kasikorn"), KW ("kbank"), KW ("scb"), KW ("krungthai"),
      KW ("ktb"), KW ("bangkokbank"), KW ("bualuang"), KW ("krungsri"),
      KW ("ttb"), KW ("gsb"), KW ("baac"), KW ("ghbank"),
      KW ("thailandpost"), KW ("thaipost"), KW ("kerry"),
      KW ("flashexpress"), KW ("lazada"), KW ("shopee"), KW ("facebook"),
      KW ("egat"), KW ("paotang"), KW ("tangrat"), KW ("revenue"),
      KW ("police"), KW ("dsi-"), KW ("-dsi"));

   Gov_Tokens : constant Keyword_List :=
     (KW ("go.th"), KW ("gov.th"), KW ("go-th"), KW ("gov-th"),
      KW ("govth"), KW ("thaigov"));

   Phish_Path_Words : constant Keyword_List :=
     (KW ("login"), KW ("signin"), KW ("sign-in"), KW ("verify"),
      KW ("update"), KW ("secure"), KW ("account"), KW ("wallet"),
      KW ("confirm"), KW ("otp"), KW ("kyc"), KW ("banking"),
      KW ("unlock"), KW ("refund"));

   Redirect_Markers : constant Keyword_List :=
     (KW ("redirect"), KW ("redir="), KW ("=http"), KW ("=%2f%2f"),
      KW ("=//"), KW ("url="), KW ("next=http"), KW ("goto="),
      KW ("continue=http"), KW ("return=http"));

   ---------------------------------------------------------------------------
   --  Local helpers
   ---------------------------------------------------------------------------
   function Is_Hex (C : Wide_Wide_Character) return Boolean is
     (Is_Digit (C) or else C in 'a' .. 'f');

   function Matches_Any_Domain (H : Text; L : Keyword_List) return Boolean is
   begin
      for I in L'Range loop
         if Is_Domain_Or_Subdomain (H, L (I)) then
            return True;
         end if;
      end loop;
      return False;
   end Matches_Any_Domain;

   -------------
   -- Analyze --
   -------------
   procedure Analyze (Input : Text; R : out Analysis_Result; Host : out Text)
   is
      U            : Text := Empty_Text;   --  trimmed, ASCII-lowered
      First        : Natural;
      Last         : Natural;
      Auth_First   : Natural;
      Auth_Last    : Natural;
      Host_First   : Natural;
      Host_Last    : Natural;
      Path_First   : Natural;
      Sep          : Natural;
      Colon        : Natural := 0;
      Removed_WS   : Boolean := False;
      Is_Official  : Boolean := False;
      Is_Ipv6      : Boolean := False;

      --  host statistics
      Labels       : Natural := 1;
      Label_Len    : Natural := 0;
      Max_Label    : Natural := 0;
      Hyphens      : Natural := 0;
      Percents     : Natural := 0;
      Empty_Label  : Boolean := False;
      Non_Ascii    : Boolean := False;
      Latin        : Boolean := False;
      Cyr_Greek    : Boolean := False;
      Alt_Dot      : Boolean := False;
      Digits_Dots  : Boolean := True;
      Hex_Chars    : Boolean := True;
      Octal_Lead   : Boolean := False;
   begin
      R    := Empty_Result;
      Host := Empty_Text;

      ------------------------------------------------------------------
      --  1. Trim surrounding whitespace
      ------------------------------------------------------------------
      First := 1;
      Last  := Input.Len;
      while First <= Last and then Is_Space (Input.Data (First)) loop
         First := First + 1;
      end loop;
      while Last >= First and then Last >= 1
        and then Is_Space (Input.Data (Last))
      loop
         Last := Last - 1;
      end loop;

      if First > Last then
         Add (R, F_Url_Malformed, 50);
         return;
      end if;

      ------------------------------------------------------------------
      --  2. Copy into U: drop invisible/bidi/internal whitespace (as
      --     browsers do for tab/LF) but REPORT that it happened.
      ------------------------------------------------------------------
      for I in First .. Last loop
         pragma Loop_Invariant (U.Len <= I - First);
         declare
            C : constant Wide_Wide_Character := Input.Data (I);
         begin
            if Is_Zero_Width (C) then
               Add (R, F_Invisible_Chars, 35);
            elsif Is_Bidi_Control (C) then
               Add (R, F_Bidi_Override, 40);
            elsif Is_Space (C) then
               Removed_WS := True;
            else
               U.Len := U.Len + 1;
               U.Data (U.Len) := Lower (C);
               if C = '%' then
                  Percents := Percents + 1;
               end if;
            end if;
         end;
      end loop;

      if Removed_WS then
         Add (R, F_Url_Encoded_Evasion, 15);
      end if;

      if U.Len = 0 then
         Add (R, F_Url_Malformed, 50);
         return;
      end if;

      ------------------------------------------------------------------
      --  3. Scheme
      ------------------------------------------------------------------
      for I in Dangerous_Schemes'Range loop
         if Starts_With (U, Dangerous_Schemes (I)) then
            Add (R, F_Url_Dangerous_Scheme, 90);
            return;   --  nothing else matters: executable / local content
         end if;
      end loop;

      if Starts_With (U, Https_Prefix) then
         Auth_First := Https_Prefix.Len + 1;
      elsif Starts_With (U, Http_Prefix) then
         Auth_First := Http_Prefix.Len + 1;
         Add (R, F_Url_No_Tls, 10);
      elsif Starts_With (U, Rel_Prefix) then
         Auth_First := Rel_Prefix.Len + 1;
      else
         Sep := Find (U, Scheme_Sep, 1, U.Len);
         if Sep /= 0 then
            Add (R, F_Url_Malformed, 15);       --  unknown scheme
            Auth_First := Sep + Scheme_Sep.Len;
         else
            Auth_First := 1;                    --  bare "example.com/..."
         end if;
      end if;

      if Auth_First > U.Len then
         Add (R, F_Url_Malformed, 50);
         return;
      end if;

      ------------------------------------------------------------------
      --  4. Authority boundaries ('\' is treated as '/' by browsers)
      ------------------------------------------------------------------
      Auth_Last := U.Len;
      for I in Auth_First .. U.Len loop
         declare
            C : constant Wide_Wide_Character := U.Data (I);
         begin
            if C = '/' or else C = '?' or else C = '#' then
               Auth_Last := I - 1;
               exit;
            elsif C = '\' then
               Add (R, F_Url_Backslash_Trick, 20);
               Auth_Last := I - 1;
               exit;
            end if;
         end;
      end loop;
      Path_First := Auth_Last + 1;

      --  backslash anywhere else is still a parser-confusion attempt
      for I in Path_First .. U.Len loop
         if U.Data (I) = '\' then
            Add (R, F_Url_Backslash_Trick, 20);
            exit;
         end if;
      end loop;

      if Auth_Last < Auth_First then
         Add (R, F_Url_Malformed, 50);
         return;
      end if;

      ------------------------------------------------------------------
      --  5. Userinfo deception: the REAL host is after the LAST '@'
      ------------------------------------------------------------------
      Host_First := Auth_First;
      for I in Auth_First .. Auth_Last loop
         if U.Data (I) = '@' then
            Host_First := I + 1;
         end if;
      end loop;
      if Host_First /= Auth_First then
         Add (R, F_Url_Userinfo, 35);
      end if;
      Host_Last := Auth_Last;

      if Host_First > Host_Last then
         Add (R, F_Url_Malformed, 50);
         return;
      end if;

      ------------------------------------------------------------------
      --  6. IPv6 literal / port
      ------------------------------------------------------------------
      if U.Data (Host_First) = '[' then
         Is_Ipv6 := True;
         Add (R, F_Url_Ip_Host, 30);
         Colon := 0;
         for I in Host_First .. Host_Last loop
            if U.Data (I) = ']' then
               Colon := I;
               exit;
            end if;
         end loop;
         if Colon = 0 or else Colon = Host_First then
            Add (R, F_Url_Malformed, 30);
            return;
         end if;
         if Colon < Host_Last then
            --  "]:port" expected
            if U.Data (Colon + 1) /= ':' then
               Add (R, F_Url_Malformed, 20);
            elsif Colon + 2 <= Host_Last then
               if not (Slice_Equals (U, Colon + 2, Host_Last, Port_443)
                       or else Slice_Equals (U, Colon + 2, Host_Last, Port_80))
               then
                  Add (R, F_Url_Nonstd_Port, 10);
               end if;
            end if;
         end if;
         Host_Last  := Colon - 1;
         Host_First := Host_First + 1;
         if Host_First > Host_Last then
            Add (R, F_Url_Malformed, 30);
            return;
         end if;
      else
         Colon := 0;
         for I in Host_First .. Host_Last loop
            if U.Data (I) = ':' then
               Colon := I;
               exit;
            end if;
         end loop;
         if Colon /= 0 then
            if Colon = Host_Last then
               null;                                 --  "host:" empty port
            elsif Host_Last - Colon > 5 then
               Add (R, F_Url_Malformed, 20);         --  port too long
            else
               for I in Colon + 1 .. Host_Last loop
                  if not Is_Digit (U.Data (I)) then
                     Add (R, F_Url_Malformed, 20);
                     exit;
                  end if;
               end loop;
               if not (Slice_Equals (U, Colon + 1, Host_Last, Port_443)
                       or else Slice_Equals (U, Colon + 1, Host_Last, Port_80))
               then
                  Add (R, F_Url_Nonstd_Port, 10);
               end if;
            end if;
            if Colon = Host_First then
               Add (R, F_Url_Malformed, 50);
               return;
            end if;
            Host_Last := Colon - 1;
         end if;
      end if;

      ------------------------------------------------------------------
      --  7. Trailing dot ("scb.co.th." bypasses naive allow-lists)
      ------------------------------------------------------------------
      if not Is_Ipv6 and then U.Data (Host_Last) = '.' then
         Add (R, F_Url_Trailing_Dot, 10);
         if Host_Last = Host_First then
            Add (R, F_Url_Malformed, 50);
            return;
         end if;
         Host_Last := Host_Last - 1;
      end if;

      if Host_Last - Host_First + 1 > Max_Host_CP then
         Add (R, F_Url_Malformed, 30);
         Host_Last := Host_First + Max_Host_CP - 1;   --  analyse prefix only
      end if;

      ------------------------------------------------------------------
      --  8. Copy host + single-pass statistics
      ------------------------------------------------------------------
      for I in Host_First .. Host_Last loop
         pragma Loop_Invariant (Host.Len <= I - Host_First);
         pragma Loop_Invariant (Host.Len <= Max_Host_CP);
         declare
            C : Wide_Wide_Character := U.Data (I);
         begin
            if Is_Alt_Dot (C) then
               Alt_Dot := True;
               C := '.';
            end if;

            if C = '.' then
               if Label_Len = 0 then
                  Empty_Label := True;
               end if;
               Labels    := Labels + 1;
               Label_Len := 0;
            else
               Label_Len := Label_Len + 1;
               Max_Label := Natural'Max (Max_Label, Label_Len);
               if Label_Len = 2 and then I >= 2 and then U.Data (I - 1) = '0'
                 and then Is_Digit (C)
               then
                  Octal_Lead := True;               --  "010.0.0.1"
               end if;
            end if;

            if C = '-' then
               Hyphens := Hyphens + 1;
            end if;
            if not Is_Ascii (C) then
               Non_Ascii := True;
            end if;
            if Is_Ascii_Letter (C) then
               Latin := True;
            end if;
            if Is_Cyrillic (C) or else Is_Greek (C) then
               Cyr_Greek := True;
            end if;
            if not (Is_Digit (C) or else C = '.') then
               Digits_Dots := False;
            end if;
            if not (Is_Hex (C) or else C = 'x' or else C = '.') then
               Hex_Chars := False;
            end if;

            Host.Len := Host.Len + 1;
            Host.Data (Host.Len) := C;
         end;
      end loop;

      if Label_Len = 0 then
         Empty_Label := True;        --  host ends with a dot after copy
      end if;

      ------------------------------------------------------------------
      --  9. Host scoring
      ------------------------------------------------------------------
      if Alt_Dot then
         Add (R, F_Url_Encoded_Evasion, 15);
      end if;
      if Non_Ascii then
         Add (R, F_Url_Unicode_Host, 30);
      end if;
      if Latin and then Cyr_Greek then
         Add (R, F_Url_Homoglyph, 40);
      end if;
      if Starts_With (Host, Xn_Prefix) or else Contains (Host, Xn_Label) then
         Add (R, F_Url_Punycode, 25);
      end if;

      if not Is_Ipv6 then
         if Digits_Dots then
            if Labels = 4 and then Max_Label <= 3 and then not Empty_Label
              and then not Octal_Lead
            then
               Add (R, F_Url_Ip_Host, 30);
            else
               Add (R, F_Url_Obfuscated_Ip, 40);   --  decimal / octal / short
            end if;
         elsif Hex_Chars and then Contains (Host, Hex_Prefix) then
            Add (R, F_Url_Obfuscated_Ip, 40);      --  0x7f.0x0.0x0.0x1
         end if;
      end if;

      if Labels > 4 then
         Add (R, F_Url_Deep_Subdomain, 15);
      end if;
      if Max_Label > 63 or else Empty_Label then
         Add (R, F_Url_Malformed, 20);
      end if;
      if Hyphens >= 3 then
         Add (R, F_Url_Many_Hyphens, 10);
      end if;

      --  TLD = text after the last '.'
      if not Is_Ipv6 and then not Digits_Dots and then Host.Len > 0 then
         declare
            Dot : Natural := 0;
         begin
            for I in reverse 1 .. Host.Len loop
               if Host.Data (I) = '.' then
                  Dot := I;
                  exit;
               end if;
            end loop;
            if Dot /= 0 and then Dot < Host.Len then
               for I in Suspicious_TLDs'Range loop
                  if Slice_Equals (Host, Dot + 1, Host.Len, Suspicious_TLDs (I))
                  then
                     Add (R, F_Url_Suspicious_Tld, 25);
                     exit;
                  end if;
               end loop;
            end if;
         end;
      end if;

      if Matches_Any_Domain (Host, Shortener_Hosts) then
         Add (R, F_Url_Shortener, 20);
      end if;

      Is_Official := not Non_Ascii
                       and then Matches_Any_Domain (Host, Official_Domains);

      if not Is_Official and then Count_Matches (Host, Brand_Tokens) > 0 then
         Add (R, F_Url_Brand_Impersonation, 40);
      end if;
      if not Is_Domain_Or_Subdomain (Host, Gov_Th)
        and then Count_Matches (Host, Gov_Tokens) > 0
      then
         Add (R, F_Url_Gov_Lookalike, 40);
      end if;

      ------------------------------------------------------------------
      --  10. Path / query / fragment
      ------------------------------------------------------------------
      if Path_First <= U.Len then
         if Contains_In (U, Apk_Ext, Path_First, U.Len) then
            Add (R, F_Url_Apk, 45);
         end if;
         for I in Phish_Path_Words'Range loop
            if Contains_In (U, Phish_Path_Words (I), Path_First, U.Len) then
               Add (R, F_Url_Phish_Path, 10);
               exit;
            end if;
         end loop;
         for I in Redirect_Markers'Range loop
            if Contains_In (U, Redirect_Markers (I), Path_First, U.Len) then
               Add (R, F_Url_Open_Redirect, 15);
               exit;
            end if;
         end loop;
      end if;

      if Percents > 10 or else Contains (U, Double_Encode) then
         Add (R, F_Url_Encoded_Evasion, 15);
      end if;
      if U.Len > 200 then
         Add (R, F_Url_Excessive_Length, 5);
      end if;

      ------------------------------------------------------------------
      --  11. Verified official destination: cap the score unless an
      --      independent high-risk signal is present.
      ------------------------------------------------------------------
      if Is_Official
        and then not Has (R, F_Url_Apk)
        and then not Has (R, F_Url_Open_Redirect)
        and then not Has (R, F_Invisible_Chars)
        and then not Has (R, F_Bidi_Override)
      then
         Add (R, F_Url_Official_Domain, 0);
         Cap (R, 10);
      end if;
   end Analyze;

end TCS_URL;
