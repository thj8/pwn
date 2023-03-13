from pwn import *

context.log_level = 'debug'
#context.terminal = ["/usr/bin/tmux", "sp", "-h"]

f_remote = True if "remote" in sys.argv else False
f_gdb = True if "gdb" in sys.argv else False

if not f_remote:
    io = remote("127.0.0.1", 49155)
else:
    io = remote("52.59.124.14", 10013)

io.sendlineafter("Easy or Hard?", "Easy")
#io.sendlineafter("Easy or Hard?", "Hard")
io.sendafter("Ready?", "\n")


def a():
    for guess in range(8):
        io.recvuntil("Before: ")
        data = io.recvuntil("\nIndex", drop=True)

        array = data.decode("utf-8").split(" ")
        lena = len(array)
        print(lena)
        input = []
        for i in range(lena):
            if i != int(array[i]):
                print(i)
                input.append(str(i))
                if len(input) == 2:
                    break

        print(input)
        if guess == 0 or guess == 4 or guess == 7:
            io.sendlineafter("1", str(359))
            io.sendlineafter("2", str(255))
        else:
            io.sendlineafter("1", input[0])
            io.sendlineafter("2", input[1])
            io.recvuntil("in")
            n = io.recvuntil("nanose")
            print(n)
            io.recvuntil("\n")


while True:
    a()
    io.recvuntil("slowiiii")
    io.sendlineafter("Easy or Hard?", "Hard")
    io.sendafter("Ready?", "\n")

io.recvall()
