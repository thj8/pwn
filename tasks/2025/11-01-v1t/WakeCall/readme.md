# 思路
- 经典代码，思路栈溢出+srop
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE buf[128]; // [rsp+0h] [rbp-80h] BYREF

  puts(s);
  read(0, buf, 0x3E8uLL);
  return 0;
}
```

# 相关题目
- read--> syscall 09-27-k17 `into the void` （需要libc）

## 其他思路，有其他magic gadget
以往都是利用`add dword ptr [rbp - 0x3d], ebx ;`, 但是本题没有`pop rbx`,所以无法用这magic

- 如果有`setvbuf`的情况下，参考09-06-imagiary/cascade

# getshell
![](https://r2.20161023.xyz/pic/20251104144841808.png)