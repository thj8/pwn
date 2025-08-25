# debug
```
00:0000│ rsp 0x7ffee07ccc70 ◂— 0x53 /* 'S' */
01:0008│-0b8 0x7ffee07ccc78 ◂— 0x430d615c0
02:0010│-0b0 0x7ffee07ccc80 ◂— 0xffffffffffffff00
03:0018│-0a8 0x7ffee07ccc88 ◂— 0xa30 /* '0\n' */
04:0020│-0a0 0x7ffee07ccc90 ◂— 0xffffffffffffff01
05:0028│-098 0x7ffee07ccc98 ◂— 0xa30 /* '0\n' */
06:0030│-090 0x7ffee07ccca0 ◂— 0xffffffffffffff02
07:0038│-088 0x7ffee07ccca8 ◂— 0xa30 /* '0\n' */
pwndbg>
08:0040│-080 0x7ffee07cccb0 ◂— 0xffffffffffffff03
09:0048│-078 0x7ffee07cccb8 ◂— 0xa30 /* '0\n' */
0a:0050│-070 0x7ffee07cccc0 ◂— 0xffffffffffffff04
0b:0058│-068 0x7ffee07cccc8 ◂— 0xa30 /* '0\n' */
0c:0060│-060 0x7ffee07cccd0 ◂— 0xffffffffffffff05
0d:0068│-058 0x7ffee07cccd8 ◂— 0xa30 /* '0\n' */
0e:0070│-050 0x7ffee07ccce0 ◂— 0xffffffffffffff06
0f:0078│-048 0x7ffee07ccce8 ◂— 0xa30 /* '0\n' */
pwndbg>
10:0080│-040 0x7ffee07cccf0 ◂— 0xffffffffffffff07
11:0088│-038 0x7ffee07cccf8 ◂— 0xa30 /* '0\n' */
12:0090│-030 0x7ffee07ccd00 ◂— 0xffffffffffffff08
13:0098│-028 0x7ffee07ccd08 ◂— 0xa30 /* '0\n' */
14:00a0│-020 0x7ffee07ccd10 ◂— 0xffffffffffffff09
15:00a8│-018 0x7ffee07ccd18 ◂— 0xa30 /* '0\n' */
16:00b0│-010 0x7ffee07ccd20 —▸ 0x7ffee07ccd30 —▸ 0x7ffee07ccd40 —▸ 0x7ffee07ccde0 —▸ 0x7ffee07cce40 ◂— ...
17:00b8│-008 0x7ffee07ccd28 ◂— 0x2509ad159ce70b00
pwndbg>
18:00c0│ rbp 0x7ffee07ccd30 —▸ 0x7ffee07ccd40 —▸ 0x7ffee07ccde0 —▸ 0x7ffee07cce40 ◂— 0
19:00c8│+008 0x7ffee07ccd38 —▸ 0x561e42a449d7 (main+118) ◂— mov eax, 0
1a:00d0│+010 0x7ffee07ccd40 —▸ 0x7ffee07ccde0 —▸ 0x7ffee07cce40 ◂— 0
1b:00d8│+018 0x7ffee07ccd48 —▸ 0x7ff030b871ca ◂— mov edi, eax
1c:00e0│+020 0x7ffee07ccd50 —▸ 0x7ffee07ccd90 —▸ 0x561e42a46d80 (__do_global_dtors_aux_fini_array_entry) —▸ 0x561e42a44200 (__do_global_dtors_aux) ◂— endbr64
1d:00e8│+028 0x7ffee07ccd58 —▸ 0x7ffee07cce68 —▸ 0x7ffee07ce55c ◂— './obligatory_heap_pwn.patch'

```
![](https://r2.20161023.xyz/pic/20250823124654391.png)


# getshell
![](https://r2.20161023.xyz/pic/20250823212728285.png)
