# 漏洞
- size传入0x3ff的时候算list，0x64，会把第一个mond当作list
- 泄漏mound，得到mmap地址->libc地址

# 利用技巧
- 把mond0地址改为anon地址
- 申请0x3ff，得到anon地址，把0xf0对应的list改为stderr附近地址
- 申请0xe8+7， 编辑为伪造的file结构
- 拷贝的fsop代码

# 堆风水
- 本解m4地址为stderr-0x10, 因为申请时回memset清空stderr数据（0xf0大小），不减0x10，会覆盖到stdout，导致异常
- 有些微调是gdb调试的产物，比如`edit(4, b"0"*0x10 + bytes(file)[:0xe0-1])`
- 远程服务器，libc的地址竟然不是0x7f,貌似是0x7？
![](https://r2.20161023.xyz/pic/20250826113042799.png)

# debug
mmap出来的地址和libc地址前面差不多,
`远程服务器的anon地址有时不是0x7f开头，所以多试几次`
![](https://r2.20161023.xyz/pic/20250826111430064.png)

# getshell
![](https://r2.20161023.xyz/pic/20250826111349295.png)