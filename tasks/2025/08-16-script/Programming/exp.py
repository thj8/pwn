from pwn import *

# context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]


io = remote("play.scriptsorcerers.xyz", 10217)
data = io.recvline().decode()
arr = data.split(" ")
num = []
n = 123456
log.success(len(arr))
log.success(arr[0])
for i in range(n):
    num.append(int(arr[i]))


def build_prefix(arr):
    prefix = [0]
    for num in arr:
        prefix.append(prefix[-1] + num)
    return prefix


prefix = build_prefix(num)


def range_sum_prefix(prefix, L, R):
    return prefix[R+1] - prefix[L]


ans = []
for i in range(n):
    data = io.recvline().decode()
    lr = data.split(" ")
    l = int(str(lr[0]))
    r = int(str(lr[1]))
    # log.success(f"{l}  {r}")
    ans.append(range_sum_prefix(prefix, l, r))

for i in range(n):
    io.sendline(str(ans[i]).encode("utf-8"))

data = io.recvall()
log.success(data)
