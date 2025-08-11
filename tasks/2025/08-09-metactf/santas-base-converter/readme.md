# 漏洞点
hex2dec函数中，能越界改写chunk_size,利用hex->dec基本都会变长的原理
![](https://r2.20161023.xyz/pic/20250811152001232.png)
![](https://r2.20161023.xyz/pic/20250811152113032.png)
![](https://r2.20161023.xyz/pic/20250811152037828.png)

# debuge
## 调试发现fopen也会malloc数据
![](https://r2.20161023.xyz/pic/20250811143640989.png)

## verify_flag
这个函数，会在堆上残留flag的值
![](https://r2.20161023.xyz/pic/20250811143854887.png)


# getshell
![](https://r2.20161023.xyz/pic/20250811163617920.png)