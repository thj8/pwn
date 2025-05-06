# 思路
```
0x0000000000110a46 : pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret # POP_RBX
0x000000000040111c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040111d : pop rbp ; ret
```

栈迁移， 把got表中read的低2个字节改为"\x46\x3a",再打magic_addr,走one_gadgetsss

# 知识点

##  libc基地址三位0x000, 改写read的got最后2个字节，可以把read变成POP_RBX
read的偏移量0x11ba50,上图中POP_RBX中偏移量为0x110a46,
所以当libc基址最后几位为0x0000 - 0x4000时加上0xba50不会发生进位，
所以可以爆破第三位，本exp中写的是"\x46\x3a", 有1/16的概率会中，吓一跳就是POP_RBX

- 注意只能是0a-4a,大了会发生进1位 

![](https://r2.20161023.xyz/pic/20250428154956039.png)


## magic addr
- add dword ptr [rbp - 0x3d], ebx ; nop ;
- rbp 设置read_got+0x3d
- ebx 设置一个delta数，（具体见下面）

## ebx计算
```
0xef4ce execve("/bin/sh", rbp-0x50, r12)
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
```
同理0x0110a46-> 0xef52b, 得到一个负数
```
>>> 0xef52b-0x0110a46
-136475
>>> hex(-136475)
'-0x2151b'

>>> hex(0xFFFFFFFF & -136475)
'0xfffdeae5'

```
![](https://r2.20161023.xyz/pic/20250428161648365.png)


# getshell
![](https://r2.20161023.xyz/pic/20250428154022846.png)