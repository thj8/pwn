from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./rev_me.out"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

encoded_str = "ZDRya2MwZGV7SzNybjNsX0s0cDNycyF9"
encoded_bytes = encoded_str.encode('utf-8')
decoded_bytes = base64.b64decode(encoded_bytes)
decoded_str = decoded_bytes.decode('utf-8')

log.success(decoded_str)
io.interactive()
