
# 思路
- 构造unsortedbin 和 tcache重叠
- 打house_of_botcake, 把fd指向unb的0x7fxxxxxx残留
- 改写最后几位，让其与stdout碰撞，大概1/16
- 修改stdout内容：flg->0xfbad1800, io_read_三个指针改为0
- 泄漏libc的相对地址，为啥泄漏出来是IO_2_1_stdin的指针呢？
- 常规操作，改free_hook，改system，free的时候直接调用system

# 知识点
1. 看相对偏移量的内存空间值，使用`tele $rebase(0x4060)`,不需要每次都vmmap再算实际地址
2. pwndbg小知识点
```
pwndbg> p stdout
$1 = (FILE *) 0x7f19015066a0 <_IO_2_1_stdout_>

pwndbg> p &main_arena
$2 = (struct malloc_state *) 0x7f1901505b80 <main_arena>

pwndbg> p _IO_2_1_stdout_
$1 = {
  file = {
    _flags = -72542208,
    _IO_read_ptr = 0x7f2bdadab723 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7f2bdadab723 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7f2bdadab723 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7f2bdadab723 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7f2bdadab723 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7f2bdadab724 <_IO_2_1_stdout_+132> "",
    _IO_buf_base = 0x7f2bdadab723 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_end = 0x7f2bdadab724 <_IO_2_1_stdout_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7f2bdadaa980 <_IO_2_1_stdin_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "\n",
    _lock = 0x7f2bdadac7e0 <_IO_stdfile_1_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7f2bdadaa880 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7f2bdada74a0 <_IO_file_jumps>
}

```
3. 构造unsortedbin 和 tcache重叠


![](https://r2.20161023.xyz/pic/20250502215219125.png)

0x511后
![](https://r2.20161023.xyz/pic/20250502215845308.png)

![](https://r2.20161023.xyz/pic/20250502220153081.png)


![](https://r2.20161023.xyz/pic/20250504225054525.png)

![](https://r2.20161023.xyz/pic/20250504230707663.png)

5. botcake
![](https://r2.20161023.xyz/pic/20250505104852424.png)

```
add(io, 12, 0x40)  
add(io, 13, 0x30)  #两次malloc, 让unb中的指针后移到19节点，里面有main_arena偏移
```
![](https://r2.20161023.xyz/pic/20250505104934870.png)

4. stdout相关
改flag，read指针
![](https://r2.20161023.xyz/pic/20250504233149150.png)
输出后
![](https://r2.20161023.xyz/pic/20250504233226346.png)


# getshell
![](https://r2.20161023.xyz/pic/20250505101419897.png)


# 看雪公众号
!(参考链接)[https://mp.weixin.qq.com/s/d3LVSyws-jrM0llxxI28dQ]


![](https://r2.20161023.xyz/pic/20250505171725154.png)
![](https://r2.20161023.xyz/pic/20250505171827284.png)
![](https://r2.20161023.xyz/pic/20250505171749380.png)