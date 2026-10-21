package body TCS_Types with SPARK_Mode => On is

   function Has (R : Analysis_Result; Code : Finding_Code) return Boolean is
   begin
      for I in 1 .. R.Count loop
         if R.Findings (I) = Code then
            return True;
         end if;
      end loop;
      return False;
   end Has;

   procedure Add (R : in out Analysis_Result; Code : Finding_Code; W : Weight)
   is
      Sum : constant Natural := Natural (R.Score) + W;   --  <= 200
   begin
      if Code = F_None or else Has (R, Code) then
         return;                                          --  idempotent
      end if;

      if R.Count < Max_Findings then
         R.Count := R.Count + 1;
         R.Findings (R.Count) := Code;
      end if;
      --  Even if the findings list is full, the score still accumulates.
      R.Score := Risk_Score (Natural'Min (Sum, 100));
   end Add;

   procedure Cap (R : in out Analysis_Result; Max : Risk_Score) is
   begin
      if R.Score > Max then
         R.Score := Max;
      end if;
   end Cap;

end TCS_Types;
