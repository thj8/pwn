# 思路
一字节溢出：

- 在edit函数中，当用户指定偏移量offset和长度length时，程序会调用fgets(note->buffer + offset, length + 2, stdin)。

- 如果offset = 0且length = 1024，则fgets可读取最多1025字节（因为length + 2 = 1026）。

- 但缓冲区note->buffer（栈上的buffer数组）大小仅为1024字节，写入1025字节会导致溢出1个字节，覆盖Note结构体的第一个字节。

# getshell
```
DEBUG] Sent 0xa bytes:
    b'cat /flag\n'
[DEBUG] Received 0x4 bytes:
    b'Bye\n'
[*] Switching to interactive mode
[DEBUG] Received 0x32 bytes:
    b'GPNCTF{NOw_y0U_5UReLY_aRe_ReadY_T0_pWN_l4dY81RD!}\n'
GPNCTF{NOw_y0U_5UReLY_aRe_ReadY_T0_pWN_l4dY81RD!}
[*] Got EOF while reading in interactive
$

```
![](https://r2.20161023.xyz/pic/20250621190955058.png)