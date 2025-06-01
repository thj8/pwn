# 思路
- 计算lastfree的时候，会计算成负数，
- 把exit的got表覆盖为win函数地址，最后两位改为0xafc9， 其中a有1/16的概率

```
if (board[7][colint] == player1symbol || board[7][colint] == player2symbol) {
    // we have to shift the entire column down
    int lastfree = 0;
    // lastfree 会搞成负数，偏移到got表？
    while (board[lastfree][colint] == player1symbol || board[lastfree][colint] == player2symbol) {
        lastfree--;
    }
    while (true) {
        if (lastfree == 7 || (board[lastfree + 1][colint] != player1symbol && board[lastfree + 1][colint] != player2symbol)) {
            board[lastfree][colint] = currsym;
            break;
        }
        board[lastfree][colint] = board[lastfree + 1][colint];
        lastfree++;
    }
}
```

# debug info
```
pwndbg> tele $rebase(0x60A0-0x80) 0x80
00:0000│  0x564462799020 (puts@got[plt]) —▸ 0x7f9ff593abe0 (puts) ◂— endbr64
01:0008│  0x564462799028 (__stack_chk_fail@got.plt) —▸ 0x564462794050 ◂— endbr64
02:0010│  0x564462799030 (setbuf@got[plt]) —▸ 0x7f9ff5942750 (setbuf) ◂— endbr64
03:0018│  0x564462799038 (system@got[plt]) —▸ 0x564462794070 ◂— endbr64
04:0020│  0x564462799040 (printf@got[plt]) —▸ 0x7f9ff5913100 (printf) ◂— endbr64
05:0028│  0x564462799048 (fgets@got[plt]) —▸ 0x564462794090 ◂— endbr64
06:0030│  0x564462799050 (getchar@got[plt]) —▸ 0x7f9ff5942100 (getchar) ◂— endbr64
07:0038│  0x564462799058 (setvbuf@got[plt]) —▸ 0x7f9ff593b550 (setvbuf) ◂— endbr64
08:0040│  0x564462799060 (exit@got[plt]) —▸ 0x5644627940c0 ◂— endbr64           # 改最后2个字节
09:0048│  0x564462799068 ◂— 0
... ↓     3 skipped
0d:0068│  0x564462799088 (__dso_handle) ◂— 0x564462799088 (__dso_handle)
0e:0070│  0x564462799090 (__dso_handle+8) ◂— 0
0f:0078│  0x564462799098 (__dso_handle+16) ◂— 0
10:0080│  0x5644627990a0 (board) ◂— 0x2020202020202020 ('        ')
... ↓     7 skipped
18:00c0│  0x5644627990e0 (stdout@GLIBC_2.2.5) —▸ 0x7f9ff5ab75c0 (_IO_2_1_stdout_) ◂— 0xfbad2887
19:00c8│  0x5644627990e8 ◂— 0
1a:00d0│  0x5644627990f0 (stdin@GLIBC_2.2.5) —▸ 0x7f9ff5ab68e0 (_IO_2_1_stdin_) ◂— 0xfbad208b
1b:00d8│  0x5644627990f8 ◂— 0
1c:00e0│  0x564462799100 (stderr@GLIBC_2.2.5) —▸ 0x7f9ff5ab74e0 (_IO_2_1_stderr_) ◂— 0xfbad2087
1d:00e8│  0x564462799108 (completed) ◂— 0x777100
1e:00f0│  0x564462799110 ◂— 0
```


win = 0x1FCD
main_game_ret = 0x2033

# getshell
![](https://r2.20161023.xyz/pic/20250601105647397.png)
![](https://r2.20161023.xyz/pic/20250601132729645.png)