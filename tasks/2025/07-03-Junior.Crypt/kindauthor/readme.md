# 思路
栈迁移 + rop


# getshell
```
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x2c bytes:
    b'flag.txt\n'
    b'ld-linux-x86-64.so.2\n'
    b'libc.so.6\n'
    b'run\n'
flag.txt
ld-linux-x86-64.so.2
libc.so.6
run
$ cat f*
[DEBUG] Sent 0x7 bytes:
    b'cat f*\n'
[DEBUG] Received 0x37 bytes:
    b'grodno{bL491M1_N4M3R3n1Y4m1_VYm05ch3n4_d0R094_v_5h3lL}\n'
grodno{bL491M1_N4M3R3n1Y4m1_VYm05ch3n4_d0R094_v_5h3lL}

```

![](https://r2.20161023.xyz/pic/20250703152800958.png)