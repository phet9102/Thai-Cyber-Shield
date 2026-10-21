package body TCS_Text with SPARK_Mode => On is

   --------
   -- KW --
   --------
   function KW (S : Wide_Wide_String) return Keyword is
      R : Keyword := (Str => (others => ' '), Len => S'Length);
   begin
      for J in 0 .. S'Length - 1 loop
         R.Str (1 + J) := Lower (S (S'First + J));
      end loop;
      return R;
   end KW;

   ----------
   -- Find --
   ----------
   function Find
     (T : Text; K : Keyword; From : Positive; Upto : CP_Length) return Natural
   is
      L : constant KW_Length := K.Len;
   begin
      if Upto < L or else From > Upto - L + 1 then
         return 0;
      end if;

      for Start in From .. Upto - L + 1 loop
         declare
            Match : Boolean := True;
         begin
            for J in 0 .. L - 1 loop
               pragma Loop_Invariant (Start + J <= Upto);
               if Lower (T.Data (Start + J)) /= K.Str (1 + J) then
                  Match := False;
                  exit;
               end if;
            end loop;
            if Match then
               return Start;
            end if;
         end;
      end loop;
      return 0;
   end Find;

   -----------------
   -- Starts_With --
   -----------------
   function Starts_With (T : Text; K : Keyword) return Boolean is
   begin
      if T.Len < K.Len then
         return False;
      end if;
      return Slice_Equals (T, 1, K.Len, K);
   end Starts_With;

   ------------------
   -- Slice_Equals --
   ------------------
   function Slice_Equals
     (T : Text; First : Positive; Last : Natural; K : Keyword) return Boolean
   is
   begin
      if Last < First or else Last - First + 1 /= K.Len then
         return False;
      end if;
      for J in 0 .. K.Len - 1 loop
         if Lower (T.Data (First + J)) /= K.Str (1 + J) then
            return False;
         end if;
      end loop;
      return True;
   end Slice_Equals;

   ----------------------------
   -- Is_Domain_Or_Subdomain --
   ----------------------------
   function Is_Domain_Or_Subdomain (Host : Text; K : Keyword) return Boolean
   is
      Start : Positive;
   begin
      if Host.Len < K.Len then
         return False;
      end if;
      Start := Host.Len - K.Len + 1;
      if not Slice_Equals (Host, Start, Host.Len, K) then
         return False;
      end if;
      --  Exact match, or the preceding character is a label separator
      return Start = 1 or else Host.Data (Start - 1) = '.';
   end Is_Domain_Or_Subdomain;

   -------------------
   -- Count_Matches --
   -------------------
   function Count_Matches (T : Text; L : Keyword_List) return Natural is
      N : Natural := 0;
   begin
      for I in L'Range loop
         pragma Loop_Invariant (N <= I - L'First);
         if Contains (T, L (I)) then
            N := N + 1;
         end if;
      end loop;
      return N;
   end Count_Matches;

   -----------------
   -- Normal_View --
   -----------------
   procedure Normal_View (Src : Text; Dst : out Text) is
   begin
      Dst := Empty_Text;
      for I in 1 .. Src.Len loop
         pragma Loop_Invariant (Dst.Len < I);
         declare
            C : constant WWC := Src.Data (I);
         begin
            if not Is_Zero_Width (C) and then not Is_Bidi_Control (C) then
               Dst.Len := Dst.Len + 1;
               Dst.Data (Dst.Len) := Normalize_Char (C);
            end if;
         end;
      end loop;
   end Normal_View;

   ------------------
   -- Compact_View --
   ------------------
   function Is_Filler (C : WWC) return Boolean is
     (Is_Space (C) or else Is_Zero_Width (C) or else Is_Bidi_Control (C)
      or else C = '.' or else C = '-' or else C = '_' or else C = '*'
      or else C = '~' or else C = ''' or else C = '"' or else C = '|'
      or else C = '+' or else C = ',');

   procedure Compact_View (Src : Text; Dst : out Text) is
   begin
      Dst := Empty_Text;
      for I in 1 .. Src.Len loop
         pragma Loop_Invariant (Dst.Len < I);
         declare
            C : constant WWC := Normalize_Char (Src.Data (I));
         begin
            if not Is_Filler (C) then
               Dst.Len := Dst.Len + 1;
               Dst.Data (Dst.Len) := C;
            end if;
         end;
      end loop;
   end Compact_View;

   -----------------------------
   -- Isolated_Thai_Fragments --
   -----------------------------
   function Isolated_Thai_Fragments (T : Text) return Natural is
      Count   : Natural := 0;
      Run     : Natural := 0;      --  current run of Thai code points
      Run_Ok  : Boolean := False;  --  run started right after a separator
      Prev_Sep : Boolean := True;  --  start of text counts as separator
   begin
      for I in 1 .. T.Len loop
         pragma Loop_Invariant (Count < I and then Run < I);
         declare
            C : constant WWC := T.Data (I);
         begin
            if Is_Thai (C) then
               if Run = 0 then
                  Run_Ok := Prev_Sep;
               end if;
               Run := Run + 1;
               Prev_Sep := False;
            else
               if Is_Filler (C) then
                  if Run in 1 .. 2 and then Run_Ok then
                     Count := Count + 1;
                  end if;
                  Prev_Sep := True;
               else
                  Prev_Sep := False;
               end if;
               Run := 0;
            end if;
         end;
      end loop;
      return Count;
   end Isolated_Thai_Fragments;

end TCS_Text;
