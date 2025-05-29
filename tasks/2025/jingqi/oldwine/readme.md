# 难点
- 往$rbp-0x12里面写，不会写到read的返回地址，图上$rsp是read的函数
- 怎么才能改返回值，到我们需要的地方呢？
- 题目中提供栈迁移方法，如果把rsp+0x8=rbp的话， $rbp-0x10rbp的话， $rbp-0x10就是read的返回值
- 每次栈最后一个字节只能固定半个，咋固定的栈迁移呢？爆破1/16？
- 改写read返回值到0x01445,看一下泄漏栈上面数据
- 下面rop走起，可以orw，execveat
![](https://r2.20161023.xyz/pic/20250529162321799.png)

```
.text:0000000000001436                 mov     edx, 6          ; n
.text:000000000000143B                 lea     rax, aSize      ; "size: "
.text:0000000000001442                 mov     rsi, rax        ; buf
.text:0000000000001445                 mov     edi, 1          ; fd
.text:000000000000144A                 call    _write
.text:000000000000144F                 lea     rax, size
.text:0000000000001456                 mov     rdi, rax
.text:0000000000001459                 call    get_int
.text:000000000000145E                 mov     edx, 7          ; n
.text:0000000000001463                 lea     rax, aIndex     ; "index: "
.text:000000000000146A                 mov     rsi, rax        ; buf
.text:000000000000146D                 mov     edi, 1          ; fd
.text:0000000000001472                 call    _write
```

# execveat execve
本题中禁用execve, 可以使用execveat
```
(pip_venv) ➜  oldwine seccomp-tools dump ./pwn
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x02 0xc000003e  if (A != ARCH_X86_64) goto 0004
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
![](https://r2.20161023.xyz/pic/20250529201153315.png)
![](https://r2.20161023.xyz/pic/20250529202240830.png)

execeeat对应rax=0x142, 也就是322

## Use execveat to open a shell

When it comes to opening a shell with system call, `execve` always pops up in mind. However, it's not always easily available due to the lack of gadgets or others constraints.  
Actually, there is a system call, `execveat`, with following prototype:

```c
int execveat(int dirfd, const char *pathname,
             char *const argv[], char *const envp[],
             int flags);
```

According to its [man page](http://man7.org/linux/man-pages/man2/execveat.2.html), it operates in the same way as `execve`. As for the additional arguments, it mentions that:

> If pathname is absolute, then dirfd is ignored.

Hence, if we make `pathname` point to `"/bin/sh"`, and set `argv`, `envp` and `flags` to 0, we can still get a shell whatever the value of `dirfd`.

# rop
没有'pop rdx, '使用' # xor edx, edx; mov eax, edx; ret'代替

# getshell
execveat执行后，会出现`cat flag`和`ls`不了的问题，他们经过讨论发现，只能执行sh他自己本身的指令,因此最后通过echo *; read FLAG < ./flag;echo $FLAG获得了flag

![](https://r2.20161023.xyz/pic/20250530002223602.png)
![](https://r2.20161023.xyz/pic/20250530003720750.png)

# 特殊syscall
```
rt_sigreturn (15)	用于 SROP（构造伪造的 sigcontext 恢复寄存器状态）
mprotect (10)	配合 shellcode 改变内存保护为可执行
mmap (9)	分配 RWX 内存执行 shellcode
exit (60)	终止程序，配合调试或测试
execveat (322)	绕过 execve 限制的常用手段
```
# 参考
[tips](https://github.com/Naetw/CTF-pwn-tips/blob/master/README.md)
[RocketMaDev](https://github.com/RocketMaDev/CTFWriteup/blob/a05539f355a0db3f37590d758e567c22c9551b79/jqctf2025/OldWine.md)
[_YFOR](https://blog.csdn.net/2502_91269216/article/details/148192972)