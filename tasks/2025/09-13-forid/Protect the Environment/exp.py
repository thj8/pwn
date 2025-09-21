from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./chall"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("", 9999)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()


# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

for i in range(0x100):
    payload = b"protect FLAG"
    io.sendlineafter("> ", payload)
    payload = b"print FLAG="
    io.sendlineafter("> ", payload)
    data = io.recvline()
    if b"FLAG" in data:
        log.success("loop count :-----> " + hex(i))
        en = data.split(b"FLAG=")[1]
        log.success(en)
        add = (i + 1) * 13

        flag = ""
        for j in range(len(en)):
            # log.success(en[j])
            # log.success(en[j] + 256 - add)
            # log.success(chr(en[j] + 256 - add))
            flag += chr(en[j] + 256 - add)
        log.success(flag)
        sleep(99999)

io.interactive()
