# 思路
fmtstr + shellcode

# debug

00:0000│ rsp 0x7ffee5a0adc0 —▸ 0x7ffee5a0b328 —▸ 0x7ffee5a0c511 ◂— 0x6c6c6168632f2e /* './chall' */
01:0008│-438 0x7ffee5a0adc8 ◂— 0x100000000
02:0010│-430 0x7ffee5a0add0 ◂— 0
03:0018│-428 0x7ffee5a0add8 ◂— 0x32b32f42e0
04:0020│-420 0x7ffee5a0ade0 ◂— 0x1a0c23d
05:0028│-418 0x7ffee5a0ade8 —▸ 0x7fccb32bbd78 ◂— 0x37ff8
06:0030│-410 0x7ffee5a0adf0 ◂— '%5$p--%10$p--%16$p\n'
07:0038│-408 0x7ffee5a0adf8 ◂— '0$p--%16$p\n'
pwndbg>
08:0040│-400 0x7ffee5a0ae00 ◂— 0x1e000a7024 /* '$p\n' */
09:0048│-3f8 0x7ffee5a0ae08 ◂— 6
0a:0050│-3f0 0x7ffee5a0ae10 —▸ 0x7ffee5a0af50 —▸ 0x7ffee5a0b210 —▸ 0x7ffee5a0b250 —▸ 0x5645be00cd90 (__do_global_dtors_aux_fini_array_entry) ◂— ...


  b'(nil)--0x1a0c23d--0x7ffee5a0af50\n'

# getshell
tjctf{sys_c4ll3d_l1nux_294835}

![](https://r2.20161023.xyz/pic/20250607213018904.png)