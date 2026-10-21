package body TCS_UTF8 with SPARK_Mode => On is

   procedure Decode
     (Raw      : Raw_Buffer;
      Raw_Len  : Raw_Length;
      Max_CP   : CP_Length;
      Result   : out Text;
      Status   : out Decode_Status)
   is
      I    : Positive := 1;     --  index into Raw
      B0   : Byte;
      Need : Natural;           --  continuation bytes still required (0..3)
      CP   : Natural;           --  accumulated code point (< 2**21)
      Min  : Natural;           --  smallest legal value for this length

      procedure Fail (S : Decode_Status) with Inline is
      begin
         Result := Empty_Text;      --  never leak a half-decoded buffer
         Status := S;
      end Fail;
   begin
      Result := Empty_Text;
      Status := Decode_Ok;

      if Raw_Len = 0 then
         Status := Decode_Empty;
         return;
      end if;

      while I <= Raw_Len loop
         pragma Loop_Invariant (Result.Len <= Max_CP);
         pragma Loop_Invariant (Result.Len < I);
         pragma Loop_Invariant (Status = Decode_Ok);

         B0 := Raw (I);

         --  Lead byte classification. 16#C0#, 16#C1# (overlong 2-byte leads),
         --  16#80#..16#BF# (stray continuation) and 16#F5#..16#FF# are illegal.
         if B0 < 16#80# then
            CP := Natural (B0);           Need := 0; Min := 0;
         elsif B0 in 16#C2# .. 16#DF# then
            CP := Natural (B0 and 16#1F#); Need := 1; Min := 16#80#;
         elsif B0 in 16#E0# .. 16#EF# then
            CP := Natural (B0 and 16#0F#); Need := 2; Min := 16#800#;
         elsif B0 in 16#F0# .. 16#F4# then
            CP := Natural (B0 and 16#07#); Need := 3; Min := 16#1_0000#;
         else
            Fail (Decode_Invalid_UTF8);
            return;
         end if;

         --  Truncated sequence at end of buffer
         if Need > Raw_Len - I then
            Fail (Decode_Invalid_UTF8);
            return;
         end if;

         for K in 1 .. Need loop
            pragma Loop_Invariant (CP < 2 ** (6 * K));   --  no overflow
            declare
               C : constant Byte := Raw (I + K);
            begin
               if (C and 16#C0#) /= 16#80# then
                  Fail (Decode_Invalid_UTF8);
                  return;
               end if;
               CP := CP * 64 + Natural (C and 16#3F#);
            end;
         end loop;

         --  Overlong / surrogate / out-of-range rejection
         if CP < Min
           or else CP > 16#10_FFFF#
           or else CP in 16#D800# .. 16#DFFF#
         then
            Fail (Decode_Invalid_UTF8);
            return;
         end if;

         --  Control character policy (NUL-byte truncation attacks, terminal
         --  escape injection, C1 "single shift" tricks)
         if (CP < 16#20# and then CP /= 9 and then CP /= 10 and then CP /= 13)
           or else CP = 16#7F#
           or else CP in 16#80# .. 16#9F#
         then
            Fail (Decode_Forbidden_Control);
            return;
         end if;

         if Result.Len >= Max_CP then
            Fail (Decode_Too_Long);
            return;
         end if;

         Result.Len := Result.Len + 1;
         Result.Data (Result.Len) := Wide_Wide_Character'Val (CP);

         exit when I + Need >= Raw_Len;     --  avoid computing I past range
         I := I + 1 + Need;
      end loop;
   end Decode;

end TCS_UTF8;
