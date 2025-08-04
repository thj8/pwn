# ben
# 知识点

## fastbin double free
在glibc2.39下可以实现fastbin的double free
1. tcache fill
2. 1->2->1

## 啥时候进入fastbin，啥时候进unsortbin
### size >= 0x420
### size < 0x80
### size >=0x80

# getshell
本地网络延迟大的时候，把`context.log_level = "debug"`注视掉再跑
![](https://r2.20161023.xyz/pic/20250804081105995.png)