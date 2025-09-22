# 思路
- setvbuf 改为pop rbx
- 利用魔法gadget`0x000000000040113c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret`, 去修改read为onegadget
- 调试时，发现pop rcx要置空，同样的原理


# debug

## setvbuf
- libc的setvbuf中存在push rbx， pop rbx, pop r12, pop r13等很多gadget
- 但是工具`ROPgadget`确查不出来，为什么呢？需要制定depth？？

![](https://r2.20161023.xyz/pic/20250916153535633.png)
![](https://r2.20161023.xyz/pic/20250916153317389.png)


# getshell
![](https://r2.20161023.xyz/pic/20250917205107117.png)