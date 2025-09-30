# 知识点

## dl_fini
![](https://r2.20161023.xyz/pic/20250930165449155.png)

exit函数执行的时候会调用dl_fini函数。



### 代码如下:
本来l->l_addr为0，而l->l_info[DT_FINI_ARRAY]->d_un.d_ptr指针指向程序中的fini_array段的地址，也就是l->l_info[DT_FINI_ARRAY]->d_un.d_ptr的值为0x0000000000403E00
```
/* First see whether an array is given.  */
if (l->l_info[DT_FINI_ARRAY] != NULL)
{
    ElfW(Addr) *array =
    (ElfW(Addr) *) (l->l_addr
            + l->l_info[DT_FINI_ARRAY]->d_un.d_ptr);
    unsigned int i = (l->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
            / sizeof (ElfW(Addr)));
    while (i-- > 0)
    ((fini_t) array[i]) ();
}
```
![](https://r2.20161023.xyz/pic/20250930103754964.png)

``` 
payload = b"%*13$p%8$n%34$hn" + p64(fini_array + (main_addr & 0xffff))[:-1]
```
太巧妙了，0x403e00+0x11d6=0x404fd6, 然而这个0x404fd6已经被设置为0x4011d6？
为啥呢?
- 因为只有23字节，*(0x403e00+Addr)=0x4011d6
- l_addr(%34$hn, 写入了0x11d6)
- 所以p64(fini_array + (main_addr & 0xffff))

With format string vulnerabilities, we have the %n specifier, which lets us write to a pointer stored on the stack. Because there is a pointer to link_map on the stack, we can write to the first 8 bytes of link_map. This is the l_addr field, which is the difference between the address in the ELF file and the address in memory where it is loaded. Because this binary is compiled without PIE, the addresses in memory are equal to the addresses in the binary, so l_addr is initially 0. But if we write to l_addr, we shift by an arbitrary offset where the linker resolves objects to!

![](https://r2.20161023.xyz/pic/20250930170002172.png)


## link_map 地址
都知道，`_dl_fixup`的第一个参数就是link_map,
![](https://r2.20161023.xyz/pic/20250930164940539.png)

正好栈上面也有这个地址，为什么呢，不深究。
![](https://r2.20161023.xyz/pic/20250930165015307.png)

## strlen 与 __strlen_avx2
![](https://r2.20161023.xyz/pic/20250930153318615.png)

# 参考链接
[点击跳转](https://eth007.me/blog/posts/valentine/)