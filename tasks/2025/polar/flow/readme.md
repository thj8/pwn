# 思路
- 整数截断漏洞：
v3 = strlen(s) 的结果被存入 unsigned __int8 类型（1字节，0-255）
当输入长度为 258 时：258 ≡ 2 (mod 256)，满足 2 <= 1u || 2 > 9u 的绕过条件
程序错误地进入 strcpy(dest, s) 分支

- 栈溢出漏洞：
dest 缓冲区仅 20 字节
strcpy 无长度检查，允许复制最多 258 字节数据
精心构造的 payload 可覆盖返回地址

- 利用链：
通过选项 3 进入 test()
发送长度 258 的 payload 触发漏洞
覆盖返回地址为 system@PLT
设置参数为 "/bin/sh" 字符串地址
最终执行 system("/bin/sh") 获取 shell

```
char *__cdecl xxx(char *s)
{
  char dest[20]; // [esp+7h] [ebp-21h] BYREF
  unsigned __int8 v3; // [esp+1Bh] [ebp-Dh]
  int v4; // [esp+1Ch] [ebp-Ch]

  printf("hello hacker!");
  v3 = strlen(s);
  if ( v3 <= 1u || v3 > 9u ) { printf("no"); }
  else {
    printf("good!");
    return strcpy(dest, s);
  }
  return (char *)v4;
}
```
# 知识点
没有ida的时候，用以下命令
```
objdump -d ./pwn1 | grep "system@plt"
strings -t x ./pwn1 | grep "/bin/sh"
```
# getshell
flag{42f03a5b-d997-41f7-9e3e-bfa290d68152}
![](https://r2.20161023.xyz/pic/20250607151708388.png)
