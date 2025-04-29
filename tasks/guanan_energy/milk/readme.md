# 解题思路
chunk 指针数组在bss上，可以通过uaf后往tcache里面插一个虚拟chunk，
这个虚拟chunk指针就为0x403528，后面申请两次就能取到这个指针，就可以任意控制每个chunk指针的内容，

- 往p1(就是chunk指针)里面写上free_got+atol_got
- 往p0写入write（本地中有write0x4012B1),此时free被改写为write
- free（1）--> write(atol_got)
- 泄漏libc
- 走system或者one_gadget都可以

![](https://r2.20161023.xyz/pic/20250429224623505.png)

# 知识点

## tcache count
调试发现在tcache 0x90中添加一个节点，发现最后一个0x15212a0无法被申请到，

![](https://r2.20161023.xyz/pic/20250429221449305.png)
![](https://r2.20161023.xyz/pic/20250429221720606.png)
![](https://r2.20161023.xyz/pic/20250429221650777.png)

原因：**tcache count被置空了**
![](https://r2.20161023.xyz/pic/20250429221758973.png)


# getshell
![](https://r2.20161023.xyz/pic/20250429225616265.png)