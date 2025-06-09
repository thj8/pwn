from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./gradeViewer"
elf = ELF(vuln_path)
libc = elf.libc


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


io = process([vuln_path]) if not f_remote else remote("tjc.tf", 31624)
io.sendlineafter("ID: ", "-62482")
io.sendlineafter("your password [a-z, 0-9]:", "f1shc0de")
io.interactive()
# tjctf{th4nk_y0u_f0r_sav1ng_m3y_grade}
