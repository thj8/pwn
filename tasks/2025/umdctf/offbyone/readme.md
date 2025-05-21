# 思路
1. 传入nan， 让其排序出错，通过调试nan会排在倒数第二个，原来紧随他的那个数，排在了最后，可以构造一个“nan 1.0”这样的数，保证1排在了max位置，
2. 使“int bin = BINS * (data[i] - min) / (max - min);”变的很大，
3. 改写ret--〉 onegadge
4. 原先ret的值是程序的地址，要怎么改为libc的地址呢？
5. vuln返回时，不能到pop rbp

![](https://r2.20161023.xyz/pic/20250521175022713.png)
## 遇到的难点
nan参与计算，会奔溃，再运算到他之前counts[bin]++;把他的值改写掉？
![](https://r2.20161023.xyz/pic/20250521141139697.png)

```
pwndbg> x/10gx ($rbp -0x9c50+4*9998)
0x7fff64da4168: 0x424800007fc00000      0x00007fff64da42a8
0x7fff64da4178: 0xb287aa939018cb00      0x00007fff64da4190
0x7fff64da4188: 0x000055c25392e533      0x0000000000000001
0x7fff64da4198: 0x00007fef505d8d90      0x0000000000000000
0x7fff64da41a8: 0x000055c25392e4c7      0x0000000164da4290
pwndbg> p *(float*)($rbp -0x9c50+4*9998)
$21 = nan(0x400000)
pwndbg> x/10gx $rbp-0x18
0x7fff64da4168: 0x424800007fc00000      0x00007fff64da42a8
0x7fff64da4178: 0xb287aa939018cb00      0x00007fff64da4190
0x7fff64da4188: 0x000055c25392e533      0x0000000000000001
0x7fff64da4198: 0x00007fef505d8d90      0x0000000000000000
0x7fff64da41a8: 0x000055c25392e4c7      0x0000000164da4290

构造bin=偏移量，让0x7fc0--> 0x8000 需要添加64次
令假max=10， min=0， 则data[i]=?
$rbp-0x9c70+2x = $rbp-0x18 +         (+遇到的2改0x7fc0 0000的高2位)
x=20013
```
![](https://r2.20161023.xyz/pic/20250521171321512.png)

one_gadget可写
0x680-0x640,
![](https://r2.20161023.xyz/pic/20250521192119316.png)
# 知识点
## movss
指令 movss xmm0, dword ptr [rbp - 0x9c50] 的解释
这是一条 x86-64 汇编指令，让我为您详细解释：

movss: 这是 "Move Scalar Single-Precision Floating-Point Value" 的缩写，用于移动单精度浮点数（32位浮点数）
xmm0: 目标寄存器，是 SSE（Streaming SIMD Extensions）扩展中的一个 128 位寄存器
dword ptr [rbp - 0x9c50]: 源操作数，表示内存地址

这条指令将内存地址 [rbp - 0x9c50] 处的单精度浮点数（32位/4字节）加载到 xmm0 寄存器的低 32 位中。具体来说：
这条指令常用于浮点数计算，特别是在处理图形、科学计算或其他需要浮点运算的应用程序中。


## divss cvttss2si
0x5615b92bb3da <vuln+349>    divss  xmm0, xmm1
0x5615b92bb3de <vuln+353>    cvttss2si eax, xmm0

divss xmm0, xmm1
将 xmm0 中的单精度浮点数除以 xmm1 中的单精度浮点1数
结果存储在 xmm0 中
cvttss2si eax, xmm0
将 xmm0 中的单精度浮点数转换为整数（截断模式），并存储到 eax 寄存器中
这是浮点数到整数的转换指令，使用截断方式（向零舍入）

# mulss
mulss xmm0, xmm1 指令解析
指令概述
mulss是x86架构中的一条SSE（Streaming SIMD Extensions）指令，全称为"Multiply Scalar Single-Precision Floating-Point Values"（乘法标量单精度浮点值）。

详细解释
这条指令执行以下操作：

将xmm0寄存器的最低32位（包含一个单精度浮点数）与xmm1寄存器的最低32位（也包含一个单精度浮点数）相乘
将乘法的结果存储在xmm0寄存器的最低32位中
xmm0寄存器的高96位（位32-127）保持不变

0x9c7c min
0x9c78 max
0x9c74 bin
0x9c70 p_counts
0x9c50 p_data
0x9c84 i

0x5610290853ca <vuln+333>    movss  xmm1, dword ptr [rbp - 0x9c78]
0x5610290853d2 <vuln+341>    subss  xmm1, dword ptr [rbp - 0x9c7c]

# gdb xmm0
```
pwndbg> p $xmm0
$4 = {
  v8_bfloat16 = {-1.075e+08, 1.094, 0, 0, 0, 0, 0, 0},
  v8_half = {-19.203, 1.8867, 0, 0, 0, 0, 0, 0},
  v4_float = {1.10000002, 0, 0, 0},
  v2_double = {5.2676887711382507e-315, 0},
  v16_int8 = {-51, -52, -116, 63, 0 <repeats 12 times>},
  v8_int16 = {-13107, 16268, 0, 0, 0, 0, 0, 0},
  v4_int32 = {1066192077, 0, 0, 0},
  v2_int64 = {1066192077, 0},
  uint128 = 1066192077
}
pwndbg> p $xmm0.v4_float[0]
$5 = 1.10000002
pwndbg>

```

![](https://r2.20161023.xyz/pic/20250521092439588.png)

# debug
p *(float*)($rbp -0x9c50+4*3)
