import random
import string
from pwn import *
context(arch='amd64', log_level='debug')
 
context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]


def generate_random_string(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string


length = 8

lose = True
while True:
    if False == lose:
        break

    st = generate_random_string(length)
    
    io = remote("192.168.2.126", 1337)
    io.sendlineafter("random):", st.encode())
   
    while True:
        data = io.recvline()
        data = data.decode()
        if "win" in data and "Joker wins! " not in data:
            pause()
        if "\n" == data:
            continue
        if "flag" in data or "ctf" in data:
            pause()
        if "seed" in data or "score" in data or "rolled" in data:
            continue

        if "Better luck next time!" in data:
            lose = True
            break

        print(data)
        if "Press Enter to roll." in data:
            io.sendline(b"")
        else:
            pause()

io.interactive()
