# 解题思路
1. stdout的fd被随机化，orw中open后的fd也是随机的
2. 本解思路，stdout=0x31，orw----> oooooooooooooorw
3. 即打开文件20次，就会形成一个连续20次的fd，本解中取0x7a
4. 其他就是常规解题思路，


大概5分钟能出flag
![](https://r2.20161023.xyz/pic/20250516133742332.png)

![](https://r2.20161023.xyz/pic/20250516134411348.png)