# debug
通过报错信息，泄漏glibc部分地址，查询得到glibc——2.23
    b"*** Error in `./pwn2': malloc(): memory corruption (fast): 0x00000000006020e0 ***\n"
[DEBUG] Received 0x16d bytes:
    b'======= Backtrace: =========\n'
    b'/lib/x86_64-linux-gnu/libc.so.6(+0x777f5)[0x7f13c424d7f5]\n'
    b'/lib/x86_64-linux-gnu/libc.so.6(+0x82679)[0x7f13c4258679]\n'
    b'/lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7f13c425a1d4]\n'
    b'./pwn2[0x400911]\n'
    b'./pwn2[0x400a93]\n'
    b'/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f13c41f6840]\n'
    b'./pwn2[0x400779]\n'
    b'======= Memory map: ========\n'

# getshell
flag{6fa8ddd3-efd9-4b86-acd1-7df3c1ab8084}

![](https://r2.20161023.xyz/pic/20250607141623944.png)