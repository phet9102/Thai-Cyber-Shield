--  ===========================================================================
--  Package : TCS_Text
--  Purpose : Bounded, allocation-free text primitives over validated Text:
--            character classes (Thai, Cyrillic, Greek, invisible, bidi),
--            anti-evasion normalisation and keyword search.
--            Every loop is bounded by Text.Len <= Max_Code_Points, so worst
--            case cost is O(Len * Keyword_Length) - no regex, no backtracking,
--            therefore no ReDoS.
--  ===========================================================================

with TCS_Types; use TCS_Types;

package TCS_Text with SPARK_Mode => On is

   subtype WWC is Wide_Wide_Character;

   ---------------------------------------------------------------------------
   --  Character classes
   ---------------------------------------------------------------------------
   function Code (C : WWC) return Natural is (WWC'Pos (C));

   function Is_Digit (C : WWC) return Boolean is (C in '0' .. '9');
   function Is_Ascii_Letter (C : WWC) return Boolean is
     (C in 'a' .. 'z' or else C in 'A' .. 'Z');
   function Is_Ascii (C : WWC) return Boolean is (Code (C) < 16#80#);
   function Is_Space (C : WWC) return Boolean is
     (C = ' ' or else Code (C) in 9 | 10 | 13 | 16#A0# | 16#3000#);

   --  Thai block U+0E00..U+0E7F
   function Is_Thai (C : WWC) return Boolean is
     (Code (C) in 16#0E00# .. 16#0E7F#);
   --  Thai digits U+0E50..U+0E59
   function Is_Thai_Digit (C : WWC) return Boolean is
     (Code (C) in 16#0E50# .. 16#0E59#);
   --  Homoglyph source scripts
   function Is_Cyrillic (C : WWC) return Boolean is
     (Code (C) in 16#0400# .. 16#052F#);
   function Is_Greek (C : WWC) return Boolean is
     (Code (C) in 16#0370# .. 16#03FF#);
   --  Fullwidth ASCII variants U+FF01..U+FF5E
   function Is_Fullwidth (C : WWC) return Boolean is
     (Code (C) in 16#FF01# .. 16#FF5E#);
   --  Zero-width / invisible formatting characters
   function Is_Zero_Width (C : WWC) return Boolean is
     (Code (C) in 16#200B# .. 16#200D# | 16#2060# | 16#FEFF# | 16#00AD#
                | 16#180E# | 16#2061# .. 16#2064#);
   --  Bidirectional overrides / isolates (Trojan-Source style spoofing)
   function Is_Bidi_Control (C : WWC) return Boolean is
     (Code (C) in 16#200E# | 16#200F# | 16#202A# .. 16#202E#
                | 16#2066# .. 16#2069#);
   --  Ideographic / fullwidth full stops that IDNA maps to '.'
   function Is_Alt_Dot (C : WWC) return Boolean is
     (Code (C) in 16#3002# | 16#FF0E# | 16#FF61#);

   --  ASCII lower-casing only (Unicode case folding is deliberately NOT
   --  applied: we want to *see* homoglyphs, not fold them away).
   function Lower (C : WWC) return WWC is
     (if C in 'A' .. 'Z' then WWC'Val (Code (C) + 32) else C);

   --  Thai digit -> ASCII digit, fullwidth -> ASCII, then ASCII lower-case.
   function Normalize_Char (C : WWC) return WWC is
     (if Is_Thai_Digit (C) then WWC'Val (Code (C) - 16#0E50# + Character'Pos ('0'))
      elsif Is_Fullwidth (C) then Lower (WWC'Val (Code (C) - 16#FF01# + 16#21#))
      else Lower (C));

   ---------------------------------------------------------------------------
   --  Fixed-capacity keywords (no unconstrained strings in tables)
   ---------------------------------------------------------------------------
   Max_KW : constant := 24;
   subtype KW_Length is Positive range 1 .. Max_KW;

   type Keyword is record
      Str : Wide_Wide_String (1 .. Max_KW);
      Len : KW_Length;
   end record;

   function KW (S : Wide_Wide_String) return Keyword
     with Global => null,
          Pre    => S'Length in KW_Length;

   type Keyword_List is array (Positive range <>) of Keyword;

   ---------------------------------------------------------------------------
   --  Search primitives (all case-insensitive for ASCII)
   ---------------------------------------------------------------------------

   --  First index >= From where K occurs within T(From .. Upto), else 0.
   function Find
     (T : Text; K : Keyword; From : Positive; Upto : CP_Length) return Natural
     with Global => null,
          Pre    => Upto <= T.Len,
          Post   => Find'Result = 0
                      or else (Find'Result >= From
                               and then Find'Result + K.Len - 1 <= Upto);

   function Contains (T : Text; K : Keyword) return Boolean is
     (Find (T, K, 1, T.Len) /= 0);

   function Contains_In
     (T : Text; K : Keyword; From : Positive; Upto : CP_Length) return Boolean
   is (Find (T, K, From, Upto) /= 0)
     with Pre => Upto <= T.Len;

   function Starts_With (T : Text; K : Keyword) return Boolean
     with Global => null;

   --  T(First .. Last) = K exactly (case-insensitive ASCII)
   function Slice_Equals
     (T : Text; First : Positive; Last : Natural; K : Keyword) return Boolean
     with Global => null,
          Pre    => Last <= T.Len;

   --  Host equals K, or ends with "." & K (proper domain-suffix match;
   --  "evilscb.co.th" does NOT match "scb.co.th").
   function Is_Domain_Or_Subdomain (Host : Text; K : Keyword) return Boolean
     with Global => null;

   --  Number of keywords from L found anywhere in T (bounded by L'Length)
   function Count_Matches (T : Text; L : Keyword_List) return Natural
     with Global => null,
          Post   => Count_Matches'Result <= L'Length;

   ---------------------------------------------------------------------------
   --  Normalisation views
   ---------------------------------------------------------------------------

   --  "Normal" view: Normalize_Char applied, zero-width & bidi removed.
   procedure Normal_View (Src : Text; Dst : out Text)
     with Global => null,
          Post   => Dst.Len <= Src.Len;

   --  "Compact" view: Normal view minus whitespace and common filler
   --  punctuation ( . - _ * ~ ' " ) used to split keywords
   --  e.g. "โ.อ.น เ-งิ-น" -> "โอนเงิน"
   procedure Compact_View (Src : Text; Dst : out Text)
     with Global => null,
          Post   => Dst.Len <= Src.Len;

   --  Count Thai fragments of 1..2 code points isolated by separators -
   --  a classic keyword-splitting evasion pattern.
   function Isolated_Thai_Fragments (T : Text) return Natural
     with Global => null,
          Post   => Isolated_Thai_Fragments'Result <= T.Len;

end TCS_Text;
