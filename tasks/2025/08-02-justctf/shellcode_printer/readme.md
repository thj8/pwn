# debug
mmap 调用：

参数：0LL（让系统选择地址）、len（页大小）、7（保护标志：PROT_READ | PROT_WRITE | PROT_EXEC，即可读、可写、可执行）、34（标志：MAP_ANONYMOUS | MAP_PRIVATE，匿名私有映射）、-1（无文件描述符）、0（无偏移）。

作用：分配一个可执行内存页（例如，地址为 P），用于存储代码或数据。如果失败，打印错误并退出。

fopen 调用：打开 /dev/null 用于写入，所有输出被丢弃。如果失败，清理资源并退出。

*addr = -61：在分配内存的起始地址 P 处写入字节 0xC3（x86 指令 ret，用于返回）。这为后续函数调用做准备。

addr -= 2：将 addr 指针减少 2 字节，现在指向 P - 2（可能无效地址，因为 P 是分配内存的起始）。循环开始时，addr 被设置为 P - 2。

## 偏移量怎么找
只能一步步debug了，不知道有没有更好的办法，跟进去fprint
![](https://r2.20161023.xyz/pic/20250802150256371.png)
![](https://r2.20161023.xyz/pic/20250802150319396.png)



# getshell
大概5分钟能出
```
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0xd bytes:
    b'flag.txt\n'
    b'run\n'
flag.txt
run
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x23 bytes:
    b'justCTF{l0w_0n_cy4n_pl34s3_r3f1ll}\n'
justCTF{l0w_0n_cy4n_pl34s3_r3f1ll}
[*] Got EOF while reading in interactive
$
```
![](https://r2.20161023.xyz/pic/20250802193827148.png)

![](https://r2.20161023.xyz/pic/20250802195445044.png)