# 漏洞点
## 任意地址读写（地址大于top_friends即可）
代码中，idx如果异常没有退出，任何情况都打印内存值，可以泄漏canary

![](https://r2.20161023.xyz/pic/20250804161954983.png)

## 栈溢出
复写canary+rbp+ret地址
![](https://r2.20161023.xyz/pic/20250804162147480.png)

# getshell
```
[DEBUG] Sent 0x2 bytes:
    b'4\n'
[*] Switching to interactive mode
[DEBUG] Received 0x23 bytes:
    b'idek{b4bys_1st_c00k1e_leak_yayyy!}\n'
idek{b4bys_1st_c00k1e_leak_yayyy!}
[*] Got EOF while reading in interactive
$

```
![](https://r2.20161023.xyz/pic/20250804161817347.png)