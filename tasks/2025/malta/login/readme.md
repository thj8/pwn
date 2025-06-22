# 思路
- `snprintf` returns the number of bytes that `it would write`, not the number that it did write. Can abuse this to zero the UID on a user since the null terminator write assumes snprintf returns a negative number if the buffer size is insufficient.
- 构造name长度，通过snprintf能覆盖uid的一个字节为0
- calloc不走tcache，所以先填满tcache，进fastbin
- 然后delete(0)， 再申请回来的时候，覆盖一个字节，两次操作就可以覆盖0x3e8这个数


# 题目错误
出题人比较马虎，出现了两个错误
![](https://r2.20161023.xyz/pic/20250622223026522.png)
![](https://r2.20161023.xyz/pic/20250622223057747.png)

# getshell
```
    b'\n'
    b'5) Exit\n'
    b'> '
[DEBUG] Sent 0x2 bytes:
    b'5\n'
[*] Switching to interactive mode
[DEBUG] Received 0x90 bytes:
    b'Hi admin, here is your flag: maltactf{always_read_the_manpages!}\n'
    b'1) Create user\n'
    b'2) Select user\n'
    b'3) Print users\n'
    b'4) Delete user\n'
    b'4) Login\n'
    b'5) Exit\n'
    b'> '
Hi admin, here is your flag: maltactf{always_read_the_manpages!}
1) Create user
2) Select user

```

![](https://r2.20161023.xyz/pic/20250622222908162.png)