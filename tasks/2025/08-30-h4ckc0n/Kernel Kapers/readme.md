# debug
```
__int64 sub_402144()
{
  __int64 v0; // rbx
  __int64 v1; // rbx
  __int64 v2; // rbx
  __int64 v3; // rbx
  __int64 v4; // rbx
  __int64 v5; // rbx
  __int64 v6; // rbx
  __int64 v7; // rbx
  __int64 result; // rax
  __int64 v9; // [rsp+0h] [rbp-140h]
  __int64 v10; // [rsp+8h] [rbp-138h]
  __int64 v11; // [rsp+10h] [rbp-130h]
  __int64 v12; // [rsp+18h] [rbp-128h]
  _QWORD v13[33]; // [rsp+20h] [rbp-120h] BYREF
  unsigned __int64 v14; // [rsp+128h] [rbp-18h]

  v14 = __readfsqword(0x28u);
  v9 = sub_401D85("ybjN");
  *(_QWORD *)(v9 + 8) = sub_401D85("MwZGV7");
  *(_QWORD *)(v9 + 16) = sub_401D85("s0cDN");
  v0 = *(_QWORD *)(v9 + 8);
  *(_QWORD *)(v0 + 8) = sub_401D85("ZDRya2");
  v1 = *(_QWORD *)(v9 + 8);
  *(_QWORD *)(v1 + 16) = sub_401D85("SzN");
  v2 = *(_QWORD *)(v9 + 16);
  *(_QWORD *)(v2 + 8) = sub_401D85("sX0");
  v3 = *(_QWORD *)(v9 + 16);
  *(_QWORD *)(v3 + 16) = sub_401D85("ycyF9");
  v10 = sub_401D85("Vh");
  *(_QWORD *)(v10 + 8) = sub_401D85("C8");
  *(_QWORD *)(v10 + 16) = sub_401D85("w");
  v4 = *(_QWORD *)(v10 + 8);
  *(_QWORD *)(v4 + 8) = sub_401D85("L3Rtc");
  v5 = *(_QWORD *)(v10 + 8);
  *(_QWORD *)(v5 + 16) = sub_401D85("ubG");
  v6 = *(_QWORD *)(v10 + 16);
  *(_QWORD *)(v6 + 8) = sub_401D85("a");
  v7 = *(_QWORD *)(v10 + 16);
  *(_QWORD *)(v7 + 16) = sub_401D85("==");
  memset(v13, 0, 256);
  sub_401E8E(v10, v13);
  v11 = sub_401EF0(v13);
  v12 = sub_419DE0(v11, "w");
  if ( !v12 )
  {
    sub_411FC0("Error opening file");
    sub_410C40(1LL);
  }
  sub_41A060("Leaked Flag: ", 1LL, 13LL, v12);
  sub_401DD7(v12, v9);
  sub_419460(v12);
  sub_401E39(v9);
  result = 0LL;
  if ( __readfsqword(0x28u) != v14 )
    sub_45A0C0();
  return result;
}
```


# pwned
![](https://r2.20161023.xyz/pic/20250830145543209.png)