# 内存值
总体大小63字节

| 偏移 |大小 | 功能|
|---|---|---|
|0          |       4|      指令个数                       | 
|0x4        |       8|      指向malloc地址，用户输入起始地址   |
|0xc(12)    |      31|      寄存器                         ｜ 
|0x2B(43)   |    n    8|      a1+12， 指向寄存器               |
|0x33(51)   |       4|      当前第几条指令                   |

# 指令结构（4个字节）
字节偏移	字段名称	数据类型	取值范围	描述
0	操作码	uint8_t	0x00-0xFF	指定操作类型（如 XOR、AND、OR 等）。
1	目标寄存器	uint8_t	0x00-0xFF	指定结果写入的寄存器编号（线性编号，范围取决于寄存器存储区大小）。
2	源类型	uint8_t	0x00 或 0x01	标记源操作数的类型：1=立即数，0=寄存器编号。
3	源值	uint8_t	0x00-0xFF	源操作数的具体值：若源类型为 0，此为立即数；若为 1，此为寄存器编号。

操作码	指令名称	功能
0x01	XOR	对两个操作数进行异或运算，结果写入目标寄存器。
0x02	AND	对两个操作数进行与运算，结果写入目标寄存器。
0x03	OR	对两个操作数进行或运算，结果写入目标寄存器。
0x04	复杂运算	执行三元运算（可能涉及进位标志），结果写入目标寄存器。

# 计算保存
把a2组，a3个寄存器，改为a4
a4范围0或1
```
_BYTE *__fastcall sub_12F6(__int64 a1, int a2, char a3, char a4)
{
  _BYTE *result; // rax

  result = (_BYTE *)(*(_QWORD *)(a1 + 43) + a2);
  *result = (a4 << a3) | ~(1 << a3) & *result;
  return result;
}
```


# 知识点

## CDQE
Convert Double word to Quad word for Extension或Convert Double word to Extened Quad word
将EAX寄存中的32位数值的符号位扩展到64位RAX寄存中高32位的每一位。

## SHL SHR
SHL, RAX, 3 ; 将RAX寄存器中的值向左逻辑移位3位
SHR RCX, 1 ; 将RCX寄存器中的值向右逻辑移位1位 

## 
   0x555c50d612da    movzx  eax, byte ptr [rax]             EAX, [0x555c50d64072] => 0
   0x555c50d612dd    movzx  edx, al                         EDX => 0


## test eax, eax 
![](https://r2.20161023.xyz/pic/20250516204204260.png)

test eax, eax 的作用是检查最低位是否为 1：

如果最低位是 1 → eax = 1 → ZF = 0 → setne al 设置 al = 1。
如果最低位是 0 → eax = 0 → ZF = 1 → setne al 设置 al = 0。


# SAR SHR
1、相同点：汇编语言中SAR和SHR指令都是右移指令，SAR是算数右移指令（shift arithmetic right），而SHR是逻辑右移指令（shift logical right）。

2、两者的在于SAR右移时保留操作数的符号，即用符号位来补足，而SHR右移时总是用0来补足。

例如10000000算数右移一位是11000000，而逻辑右移一位是01000000。

3、用法不同：

SAR功能是将操作数右移，符号位保持不变，可用于有符号数除法；
SHR功能是将操作数右移，原最低位移入进位标志CF，原最高位补0；可用于无符号数除法.


# 截图
![](https://r2.20161023.xyz/pic/20250517111555615.png)
![](https://r2.20161023.xyz/pic/20250517142931262.png)


# getshell
![](https://r2.20161023.xyz/pic/20250518004022993.png)
![](https://r2.20161023.xyz/pic/20250518004045483.png)


#   知识点
```
什么是“全加器”？
全加器（full adder） 是数字电路中用于加两个 bit 加上进位的基本单元。

输入：
A: 第一个输入 bit

B: 第二个输入 bit

Cin: 上一位的进位

输出：
Sum: A + B + Cin 的最低位

Cout: A + B + Cin 的进位（高位）

全加器的真值表：
A	B	Cin	Sum	Cout
0	0	0	0	0
0	0	1	1	0
0	1	0	1	0
0	1	1	0	1
1	0	0	1	0
1	0	1	0	1
1	1	0	0	1
1	1	1	1	1

本质：
Sum = A ^ B ^ Cin
Cout = (A & B) | (Cin & (A ^ B)) 或 Cout = (Cin & (A | B)) | (A & B)（你这边是后一种）


```