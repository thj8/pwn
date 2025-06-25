# 思路
- tcache posioning
- off-by-one

![](https://r2.20161023.xyz/pic/20250625140415833.png)


# 知识点

## unsortedbin, malloc
- unsorted中划出0x18，后内存值如图
- 一下子就可以泄漏出libc 和 heap
![](https://r2.20161023.xyz/pic/20250624092133410.png)

# getshell
```
    b'ls\n'
[DEBUG] Received 0x10 bytes:
    b'chall\n'
    b'flag\n'
    b'libs\n'
chall
flag
libs
$ cat f*
[DEBUG] Sent 0x7 bytes:
    b'cat f*\n'
[DEBUG] Received 0x38 bytes:
    b'corn{tUrN5_out_Th3r3_reaLLy_was_some_pOison_in_Th3_enD}\n'
corn{tUrN5_out_Th3r3_reaLLy_was_some_pOison_in_Th3_enD}
[*] Got EOF while reading in interactive

```
![](https://r2.20161023.xyz/pic/20250624160548553.png)