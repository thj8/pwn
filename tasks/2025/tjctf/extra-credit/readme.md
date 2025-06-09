# 思路
0x0BEE 的带符号short值是 `3054` (正数)

在32位int中表示为 `0x00000BEE`,但若构造为`0xFFFF0BEE`,十进制值为 `-62482` (满足 <= 10),低2字节仍是 `0x0BEE`

# getshell
tjctf{th4nk_y0u_f0r_sav1ng_m3y_grade}

![](https://r2.20161023.xyz/pic/20250607122958459.png)