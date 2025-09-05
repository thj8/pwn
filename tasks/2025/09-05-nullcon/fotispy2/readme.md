# debug
```
pwndbg> telescope 0x7ffcd3b8aa80-0x10
00:0000│  0x7ffcd3b8aa70 ◂— 0x6333000000000000
01:0008│  0x7ffcd3b8aa78 ◂— 0x28b5d83c56bde200
02:0010│  0x7ffcd3b8aa80 ◂— 1
03:0018│  0x7ffcd3b8aa88 —▸ 0x7fb93c68924a ◂— mov edi, eax
04:0020│  0x7ffcd3b8aa90 —▸ 0x7ffcd3b8ab80 —▸ 0x7ffcd3b8ab88 ◂— 0x38 /* '8' */
05:0028│  0x7ffcd3b8aa98 —▸ 0x5625cdcd68f4 ◂— push rbp
06:0030│  0x7ffcd3b8aaa0 ◂— 0x1cdcd5040
07:0038│  0x7ffcd3b8aaa8 —▸ 0x7ffcd3b8ab98 —▸ 0x7ffcd3b8c566 ◂— './fotispy2.patch'
pwndbg>
08:0040│  0x7ffcd3b8aab0 —▸ 0x7ffcd3b8ab98 —▸ 0x7ffcd3b8c566 ◂— './fotispy2.patch'
09:0048│  0x7ffcd3b8aab8 ◂— 0x18e6da6549c7ef1
0a:0050│  0x7ffcd3b8aac0 ◂— 0
0b:0058│  0x7ffcd3b8aac8 —▸ 0x7ffcd3b8aba8 —▸ 0x7ffcd3b8c577 ◂— 'HOME=/root'
0c:0060│  0x7ffcd3b8aad0 —▸ 0x5625cdcd8dd8 —▸ 0x5625cdcd6190 ◂— endbr64
0d:0068│  0x7ffcd3b8aad8 —▸ 0x7fb93c878020 (_rtld_global) —▸ 0x7fb93c8792e0 —▸ 0x5625cdcd5000 ◂— 0x10102464c457f
0e:0070│  0x7ffcd3b8aae0 ◂— 0xfe77cad701be7ef1
0f:0078│  0x7ffcd3b8aae8 ◂— 0xfefc1577709a7ef1
pwndbg>
10:0080│  0x7ffcd3b8aaf0 ◂— 0
... ↓     2 skipped
13:0098│  0x7ffcd3b8ab08 —▸ 0x7ffcd3b8ab98 —▸ 0x7ffcd3b8c566 ◂— './fotispy2.patch'
14:00a0│  0x7ffcd3b8ab10 —▸ 0x7ffcd3b8ab98 —▸ 0x7ffcd3b8c566 ◂— './fotispy2.patch'
15:00a8│  0x7ffcd3b8ab18 ◂— 0x28b5d83c56bde200
16:00b0│  0x7ffcd3b8ab20 ◂— 0xd /* '\r' */
17:00b8│  0x7ffcd3b8ab28 —▸ 0x7fb93c689305 (__libc_start_main+133) ◂— mov r15, qword ptr [rip + 0x1aac6c]
pwndbg>
18:00c0│  0x7ffcd3b8ab30 —▸ 0x5625cdcd68f4 ◂— push rbp
19:00c8│  0x7ffcd3b8ab38 —▸ 0x5625cdcd8dd8 —▸ 0x5625cdcd6190 ◂— endbr64
1a:00d0│  0x7ffcd3b8ab40 ◂— 0
... ↓     2 skipped
1d:00e8│  0x7ffcd3b8ab58 —▸ 0x5625cdcd60f0 ◂— endbr64
1e:00f0│  0x7ffcd3b8ab60 —▸ 0x7ffcd3b8ab90 ◂— 1
1f:00f8│  0x7ffcd3b8ab68 ◂— 0


00:0000│ rsp 0x7ffcd3b24dd0 —▸ 0x7ffcd3b8aba8 —▸ 0x7ffcd3b8c577 ◂— 'HOME=/root'
01:0008│-018 0x7ffcd3b24dd8 —▸ 0x7ffcd3b24e00 —▸ 0x5625cf9c72a0 ◂— 0x746166796e6974 /* 'tinyfat' */
02:0010│-010 0x7ffcd3b24de0 ◂— 0x3c878020
03:0018│-008 0x7ffcd3b24de8 —▸ 0x7ffcd3b24e14 ◂— 0x6161616161616161 ('aaaaaaaa')
04:0020│ rbp 0x7ffcd3b24df0 —▸ 0x7ffcd3b8aa80 ◂— 1
05:0028│+008 0x7ffcd3b24df8 —▸ 0x5625cdcd69e5 ◂— jmp 0x5625cdcd6a00
06:0030│+010 0x7ffcd3b24e00 —▸ 0x5625cf9c72a0 ◂— 0x746166796e6974 /* 'tinyfat' */
07:0038│+018 0x7ffcd3b24e08 —▸ 0x5625cf9c72d0 ◂— 0x746166796e6974 /* 'tinyfat' */



0x7ffcd3b24dd0 —▸ 0x7ffcd3b8aba8        %6$p

0x7ffcd3b8aa88 —▸ 0x7fb93c68924a    


0x7ffcd3b24e14 - 0x7ffcd3b24df8
```

# getshell
![](https://r2.20161023.xyz/pic/20250905143418391.png)