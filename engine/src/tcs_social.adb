with TCS_Text; use TCS_Text;
with TCS_URL;

package body TCS_Social with SPARK_Mode => On is

   ---------------------------------------------------------------------------
   --  Tables
   ---------------------------------------------------------------------------
   Scheme_Sep  : constant Keyword := KW ("://");
   Profile_Php : constant Keyword := KW ("profile.php");
   Id_Eq       : constant Keyword := KW ("id=");
   Share_Path  : constant Keyword := KW ("/share/");
   Shim_Path   : constant Keyword := KW ("/l.php");
   Market_Path : constant Keyword := KW ("/marketplace/");
   Shim_Host_1 : constant Keyword := KW ("l.");
   Shim_Host_2 : constant Keyword := KW ("lm.");

   Facebook_Hosts : constant Keyword_List :=
     (KW ("facebook.com"), KW ("fb.com"), KW ("fb.me"), KW ("fb.watch"),
      KW ("messenger.com"), KW ("fbcdn.net"));

   Fb_Lookalike_Tokens : constant Keyword_List :=
     (KW ("facebook"), KW ("faceb00k"), KW ("facebo0k"), KW ("fac3book"), KW ("facebk"), KW ("fb-"), KW ("-fb"),
      KW ("fbsupport"), KW ("fbhelp"), KW ("meta-"), KW ("-meta"),
      KW ("metasupport"), KW ("metabusiness"), KW ("meta-business"),
      KW ("messenger-"));

   Phish_Words : constant Keyword_List :=
     (KW ("checkpoint"), KW ("recover"), KW ("appeal"), KW ("copyright"),
      KW ("violation"), KW ("verify"), KW ("confirm"), KW ("help-center"),
      KW ("business-support"), KW ("login"), KW ("unlock"));

   Free_Providers : constant Keyword_List :=
     (KW ("gmail.com"), KW ("googlemail.com"), KW ("hotmail.com"),
      KW ("hotmail.co.th"), KW ("outlook.com"), KW ("live.com"),
      KW ("yahoo.com"), KW ("yahoo.co.th"), KW ("icloud.com"),
      KW ("proton.me"), KW ("protonmail.com"), KW ("gmx.com"),
      KW ("yandex.com"), KW ("mail.com"), KW ("aol.com"));

   Disposable_Providers : constant Keyword_List :=
     (KW ("mailinator.com"), KW ("10minutemail.com"), KW ("temp-mail.org"),
      KW ("tempmail.com"), KW ("guerrillamail.com"), KW ("yopmail.com"),
      KW ("trashmail.com"), KW ("sharklasers.com"), KW ("getnada.com"),
      KW ("dispostable.com"), KW ("maildrop.cc"), KW ("throwawaymail.com"),
      KW ("emailondeck.com"), KW ("mohmal.com"));

   Brand_Local_Tokens : constant Keyword_List :=
     (KW ("kbank"), KW ("kasikorn"), KW ("scb"), KW ("krungthai"),
      KW ("ktb"), KW ("bangkokbank"), KW ("krungsri"), KW ("ttb"),
      KW ("gsb"), KW ("truemoney"), KW ("shopee"), KW ("lazada"),
      KW ("facebook"), KW ("meta"), KW ("revenue"), KW ("police"),
      KW ("dsi"), KW ("gov"), KW ("bank"), KW ("thailandpost"),
      KW ("kerry"), KW ("flash"));

   Generic_Official_Tokens : constant Keyword_List :=
     (KW ("support"), KW ("official"), KW ("admin"), KW ("security"),
      KW ("callcenter"), KW ("helpdesk"), KW ("service"), KW ("verify"));

   ---------------------------------------------------------------------------
   function Matches_Domain (H : Text; L : Keyword_List) return Boolean is
   begin
      for I in L'Range loop
         if Is_Domain_Or_Subdomain (H, L (I)) then
            return True;
         end if;
      end loop;
      return False;
   end Matches_Domain;

   ----------------------
   -- Analyze_Facebook --
   ----------------------
   procedure Analyze_Facebook
     (Input : Text; R : out Analysis_Result; Host : out Text)
   is
      U          : Text := Empty_Text;    --  lower-cased, blanks removed
      Sep        : Natural;
      Start      : Positive;
      Path_First : Natural := 0;
      Id_Pos     : Natural;
      Id_Digits  : Natural := 0;
   begin
      --  1. Full generic URL analysis first (defence in depth)
      TCS_URL.Analyze (Input, R, Host);
      if Has (R, F_Url_Dangerous_Scheme) or else Host.Len = 0 then
         return;
      end if;

      --  2. Normalised copy to locate the path
      for I in 1 .. Input.Len loop
         pragma Loop_Invariant (U.Len < I);
         declare
            C : constant Wide_Wide_Character := Input.Data (I);
         begin
            if not (Is_Space (C) or else Is_Zero_Width (C)
                    or else Is_Bidi_Control (C))
            then
               U.Len := U.Len + 1;
               U.Data (U.Len) := Lower (C);
            end if;
         end;
      end loop;

      Sep   := Find (U, Scheme_Sep, 1, U.Len);
      Start := (if Sep /= 0 then Sep + Scheme_Sep.Len else 1);
      for I in Start .. U.Len loop
         if U.Data (I) = '/' or else U.Data (I) = '?' or else U.Data (I) = '#'
         then
            Path_First := I;
            exit;
         end if;
      end loop;

      --  3. Facebook-family structure
      if Matches_Domain (Host, Facebook_Hosts) then
         Add (R, F_So_Facebook_Official, 0);

         if Path_First /= 0 then
            if Contains_In (U, Profile_Php, Path_First, U.Len) then
               Id_Pos := Find (U, Id_Eq, Path_First, U.Len);
               if Id_Pos /= 0 then
                  Add (R, F_So_Profile_Numeric, 0);
                  for I in Id_Pos + Id_Eq.Len .. U.Len loop
                     exit when not Is_Digit (U.Data (I));
                     Id_Digits := Id_Digits + 1;
                  end loop;
                  --  Weak signal: the 615... 15-digit ID range is assigned
                  --  to recently created accounts.
                  if Id_Digits >= 15
                    and then Id_Pos + Id_Eq.Len + 2 <= U.Len
                    and then U.Data (Id_Pos + Id_Eq.Len) = '6'
                    and then U.Data (Id_Pos + Id_Eq.Len + 1) = '1'
                    and then U.Data (Id_Pos + Id_Eq.Len + 2) = '5'
                  then
                     Add (R, F_So_New_Account_Id, 15);
                  end if;
               end if;
            end if;

            if Contains_In (U, Share_Path, Path_First, U.Len) then
               Add (R, F_So_Share_Link, 5);
            end if;
            if (Starts_With (Host, Shim_Host_1) or else Starts_With (Host, Shim_Host_2))
              and then Contains_In (U, Shim_Path, Path_First, U.Len)
            then
               Add (R, F_So_Link_Shim, 10);
            end if;
            if Contains_In (U, Market_Path, Path_First, U.Len) then
               Add (R, F_So_Marketplace, 0);
            end if;
         end if;

      elsif Count_Matches (Host, Fb_Lookalike_Tokens) > 0 then
         --  4. Not Facebook, but dressed as Facebook / Meta
         Add (R, F_So_Fb_Lookalike, 70);
         if Path_First /= 0 then
            for I in Phish_Words'Range loop
               if Contains_In (U, Phish_Words (I), Path_First, U.Len) then
                  Add (R, F_So_Phish_Path, 40);
                  exit;
               end if;
            end loop;
         end if;
      end if;
   end Analyze_Facebook;

   -------------------
   -- Analyze_Email --
   -------------------
   function Local_Char_Ok (C : Wide_Wide_Character) return Boolean is
     (C in 'a' .. 'z' or else C in '0' .. '9' or else C = '.'
      or else C = '_' or else C = '%' or else C = '+' or else C = '-');

   function Domain_Char_Ok (C : Wide_Wide_Character) return Boolean is
     (C in 'a' .. 'z' or else C in '0' .. '9' or else C = '.' or else C = '-');

   procedure Analyze_Email
     (Input : Text; R : out Analysis_Result; Host : out Text)
   is
      T        : Text := Empty_Text;   --  trimmed, lower-cased
      Local    : Text := Empty_Text;
      Dom      : Text := Empty_Text;
      First    : Positive := 1;
      Last     : Natural  := Input.Len;
      At_Pos   : Natural  := 0;
      At_Count : Natural  := 0;
      N_Digits : Natural  := 0;
      Valid    : Boolean  := True;
      Is_Free  : Boolean;
   begin
      R    := Empty_Result;
      Host := Empty_Text;

      while First <= Last and then Is_Space (Input.Data (First)) loop
         First := First + 1;
      end loop;
      while Last >= First and then Is_Space (Input.Data (Last)) loop
         Last := Last - 1;
      end loop;
      if First > Last then
         Add (R, F_Em_Invalid, 40);
         return;
      end if;

      for I in First .. Last loop
         pragma Loop_Invariant (T.Len = I - First);
         T.Len := T.Len + 1;
         T.Data (T.Len) := Lower (Input.Data (I));
      end loop;

      for I in 1 .. T.Len loop
         if not Is_Ascii (T.Data (I)) then
            Add (R, F_Em_Unicode, 40);         --  homoglyph-capable address
            Add (R, F_Em_Invalid, 40);
            return;
         end if;
         if T.Data (I) = '@' then
            At_Count := At_Count + 1;
            At_Pos   := I;
         end if;
      end loop;

      if At_Count /= 1 or else At_Pos <= 1 or else At_Pos >= T.Len
        or else At_Pos - 1 > 64 or else T.Len - At_Pos > 253
      then
         Add (R, F_Em_Invalid, 40);
         return;
      end if;

      --  local part
      for I in 1 .. At_Pos - 1 loop
         pragma Loop_Invariant (Local.Len = I - 1);
         declare
            C : constant Wide_Wide_Character := T.Data (I);
         begin
            if not Local_Char_Ok (C) then
               Valid := False;
            end if;
            if C = '.' and then (I = 1 or else I = At_Pos - 1
                                 or else T.Data (I + 1) = '.')
            then
               Valid := False;
            end if;
            if Is_Digit (C) then
               N_Digits := N_Digits + 1;
            end if;
            Local.Len := Local.Len + 1;
            Local.Data (Local.Len) := C;
         end;
      end loop;

      --  domain part
      for I in At_Pos + 1 .. T.Len loop
         pragma Loop_Invariant (Dom.Len = I - At_Pos - 1);
         declare
            C : constant Wide_Wide_Character := T.Data (I);
         begin
            if not Domain_Char_Ok (C) then
               Valid := False;
            end if;
            Dom.Len := Dom.Len + 1;
            Dom.Data (Dom.Len) := C;
         end;
      end loop;

      if Dom.Len < 3
        or else Dom.Data (1) = '.' or else Dom.Data (1) = '-'
        or else Dom.Data (Dom.Len) = '.' or else Dom.Data (Dom.Len) = '-'
      then
         Valid := False;
      end if;
      declare
         Has_Dot : Boolean := False;
      begin
         for I in 1 .. Dom.Len loop
            if Dom.Data (I) = '.' then
               Has_Dot := True;
               if I < Dom.Len and then Dom.Data (I + 1) = '.' then
                  Valid := False;
               end if;
            end if;
         end loop;
         if not Has_Dot then
            Valid := False;
         end if;
      end;

      if not Valid then
         Add (R, F_Em_Invalid, 40);
         return;
      end if;

      --  Domain gets the full host analysis (look-alike banks, punycode,
      --  suspicious TLD ...). Its result becomes the base result.
      TCS_URL.Analyze (Dom, R, Host);

      Is_Free := Matches_Domain (Dom, Free_Providers);

      if Matches_Domain (Dom, Disposable_Providers) then
         Add (R, F_Em_Disposable, 40);
      end if;
      if Is_Free then
         Add (R, F_Em_Free_Provider, 0);
         if Count_Matches (Local, Brand_Local_Tokens) > 0 then
            Add (R, F_Em_Brand_In_Free, 45);     --  "kbank.support@gmail.com"
         elsif Count_Matches (Local, Generic_Official_Tokens) > 0 then
            Add (R, F_Em_Brand_In_Free, 20);     --  "official.admin@gmail.com"
         end if;
      end if;
      if N_Digits >= 6 then
         Add (R, F_Em_Digit_Heavy, 10);
      end if;
   end Analyze_Email;

end TCS_Social;
