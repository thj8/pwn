 # debug
 ```
 RAX  8
 RBX  0x7ffd141f5be8 —▸ 0x7ffd141f659a ◂— 0x48006e69616d2f2e /* './main' */
 RCX  0x7f1225faa574 (write+20) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0
 RDI  0
 RSI  0x7f1226092643 (_IO_2_1_stdout_+131) ◂— 0x93710000000000a /* '\n' */
 R8   7
 R9   1
 R10  0x7f1225e9eeb8 ◂— 0x11001a00000a0e
 R11  0x202
 R12  1
 R13  0
 R14  0x55b380906dd8 —▸ 0x55b3809041a0 ◂— endbr64
 R15  0x7f12260e7000 (_rtld_global) —▸ 0x7f12260e82e0 —▸ 0x55b380903000 ◂— 0x10102464c457f
 RBP  0x7ffd141f5ac0 —▸ 0x7ffd141f5b60 —▸ 0x7ffd141f5bc0 ◂— 0
*RSP  0x7ffd141f5a98 —▸ 0x55b380904386 ◂— add byte ptr [rax], al
*RIP  0x55b3809040e0 (exit@plt) ◂— endbr64
```
![](https://r2.20161023.xyz/pic/20250826164658616.png)


# dynstr
```
0x000055e899baa098 - 0x000055e899baa0c8 is .gnu.hash
0x000055e899bab000 - 0x000055e899bab0ec is .dynstr
0x000055e899bab0f0 - 0x000055e899bab2e0 is .dynamic
0x00007f5ca18612a8 - 0x00007f5ca18612c8 is .note.gnu.property in /lib64/ld-linux-x86-64.so.2
0x00007f5ca18612c8 - 0x00007f5ca18612ec is .note.gnu.build-id in /lib64/ld-linux-x86-64.so.2
0x00007f5ca18612f0 - 0x00007f5ca186142c is .hash in /lib64/ld-linux-x86-64.so.2
```
![](https://r2.20161023.xyz/pic/20250827134619322.png)


```
(pip_venv) ➜  no nonsense readelf -p .dynstr main

String dump of section '.dynstr':
  [     1]  puts
  [     6]  exit
  [     b]  setbuf
  [    12]  read
  [    17]  strstr
  [    1e]  stdout
  [    25]  __libc_start_main
  [    37]  stderr
  [    3e]  __cxa_finalize
  [    4d]  __isoc99_scanf
  [    5c]  libc.so.6
  [    66]  GLIBC_2.7
  [    70]  GLIBC_2.2.5
  [    7c]  GLIBC_2.34
  [    87]  _ITM_deregisterTMCloneTable
  [    a3]  __gmon_start__
  [    b2]  _ITM_registerTMCloneTable
  [    cc]  /lib/x86_64-linux-gnu/libc.so.6
```
# 参考
![](https://r2.20161023.xyz/pic/20250827165039142.png)

# getshell
![](https://r2.20161023.xyz/pic/20250827134749152.png)