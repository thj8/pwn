# 思路
覆盖printf的返回地址+ROP

# 误区
_exit()退出，不是leave ret，不会经过常见的rop，
不会触发fileio的clean操作，不会触发overflow，

# getshell
![](https://r2.20161023.xyz/pic/20250824235835445.png)