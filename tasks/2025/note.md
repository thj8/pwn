# debug libc
set debug-file-directory
directory

# readelf -d tt
(pip_venv) ➜  /tmp readelf -d tt

Dynamic section at offset 0x60c8 contains 27 entries:
  Tag        Type                         Name/Value
 0x000000000000001d (RUNPATH)            Library runpath: [/root/glibc-all-in-one/libs/2.35-0ubuntu3.10_amd64/]
 0x0000000000000001 (NEEDED)             Shared library: [/home/glibc_source/glibcs/libc-2.35.so]
 0x000000000000000c (INIT)               0x1000
 0x000000000000000d (FINI)               0x1184
 0x0000000000000019 (INIT_ARRAY)         0x3dd0
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x3dd8
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x50c0
 0x0000000000000005 (STRTAB)             0x8000
 0x0000000000000006 (SYMTAB)             0x50e8
 0x000000000000000a (STRSZ)              232 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0x3fe8
 0x0000000000000002 (PLTRELSZ)           24 (bytes)
 0x0000000000000014 (PLTREL)             RELA
 0x0000000000000017 (JMPREL)             0x610
 0x0000000000000007 (RELA)               0x550
 0x0000000000000008 (RELASZ)             192 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000006ffffffb (FLAGS_1)            Flags: PIE
 0x000000006ffffffe (VERNEED)            0x520
 0x000000006fffffff (VERNEEDNUM)         1
 0x000000006ffffff0 (VERSYM)             0x50e
 0x000000006ffffff9 (RELACOUNT)          3
 0x0000000000000000 (NULL)               0x0

# readelf -S tt
(pip_venv) ➜  /tmp readelf -S tt
There are 38 section headers, starting at offset 0x3948:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .gnu.version      VERSYM           000000000000050e  0000050e
       000000000000000e  0000000000000002   A      34     0     2
  [ 2] .gnu.version_r    VERNEED          0000000000000520  00000520
       0000000000000030  0000000000000000   A      36     1     8
  [ 3] .rela.dyn         RELA             0000000000000550  00000550
       00000000000000c0  0000000000000018   A      34     0     8
  [ 4] .rela.plt         RELA             0000000000000610  00000610
       0000000000000018  0000000000000018  AI      34    17     8
  [ 5] .init             PROGBITS         0000000000001000  00001000
       000000000000001b  0000000000000000  AX       0     0     4
  [ 6] .plt              PROGBITS         0000000000001020  00001020
       0000000000000020  0000000000000010  AX       0     0     16
  [ 7] .plt.got          PROGBITS         0000000000001040  00001040
       0000000000000010  0000000000000010  AX       0     0     16
  [ 8] .plt.sec          PROGBITS         0000000000001050  00001050
       0000000000000010  0000000000000010  AX       0     0     16
  [ 9] .text             PROGBITS         0000000000001060  00001060
       0000000000000121  0000000000000000  AX       0     0     16
  [10] .fini             PROGBITS         0000000000001184  00001184
       000000000000000d  0000000000000000  AX       0     0     4
  [11] .rodata           PROGBITS         0000000000002000  00002000
       000000000000000c  0000000000000000   A       0     0     4
  [12] .eh_frame_hdr     PROGBITS         000000000000200c  0000200c
       0000000000000034  0000000000000000   A       0     0     4
  [13] .eh_frame         PROGBITS         0000000000002040  00002040
       00000000000000ac  0000000000000000   A       0     0     8
  [14] .init_array       INIT_ARRAY       0000000000003dd0  00002dd0
       0000000000000008  0000000000000008  WA       0     0     8
  [15] .fini_array       FINI_ARRAY       0000000000003dd8  00002dd8
       0000000000000008  0000000000000008  WA       0     0     8
  [16] .got              PROGBITS         0000000000003fc0  00002fc0
       0000000000000028  0000000000000008  WA       0     0     8
  [17] .got.plt          PROGBITS         0000000000003fe8  00002fe8
       0000000000000020  0000000000000008  WA       0     0     8
  [18] .data             PROGBITS         0000000000004008  00003008
       0000000000000010  0000000000000000  WA       0     0     8
  [19] .bss              NOBITS           0000000000004018  00003018
       0000000000000008  0000000000000000  WA       0     0     1
  [20] .comment          PROGBITS         0000000000000000  00003018
       000000000000002b  0000000000000001  MS       0     0     1
  [21] .debug_aranges    PROGBITS         0000000000000000  00003043
       0000000000000030  0000000000000000           0     0     1
  [22] .debug_info       PROGBITS         0000000000000000  00003073
       000000000000009a  0000000000000000           0     0     1
  [23] .debug_abbrev     PROGBITS         0000000000000000  0000310d
       0000000000000054  0000000000000000           0     0     1
  [24] .debug_line       PROGBITS         0000000000000000  00003161
       0000000000000054  0000000000000000           0     0     1
  [25] .debug_str        PROGBITS         0000000000000000  000031b5
       00000000000000d9  0000000000000001  MS       0     0     1
  [26] .debug_line_str   PROGBITS         0000000000000000  0000328e
       0000000000000009  0000000000000001  MS       0     0     1
  [27] .symtab           SYMTAB           0000000000000000  00003298
       0000000000000360  0000000000000018          28    18     8
  [28] .strtab           STRTAB           0000000000000000  000035f8
       00000000000001d7  0000000000000000           0     0     1
  [29] .shstrtab         STRTAB           0000000000000000  000037cf
       0000000000000173  0000000000000000           0     0     1
  [30] .note.gnu.pr[...] NOTE             0000000000005048  00005048
       0000000000000030  0000000000000000   A       0     0     8
  [31] .note.gnu.bu[...] NOTE             0000000000005078  00005078
       0000000000000024  0000000000000000   A       0     0     4
  [32] .note.ABI-tag     NOTE             00000000000050a0  000050a0
       0000000000000020  0000000000000000   A       0     0     4
  [33] .gnu.hash         GNU_HASH         00000000000050c0  000050c0
       0000000000000024  0000000000000000   A      34     0     8
  [34] .dynsym           DYNSYM           00000000000050e8  000050e8
       00000000000000a8  0000000000000018   A      36     1     8
  [35] .dynamic          DYNAMIC          00000000000060c8  000060c8
       00000000000001f0  0000000000000010  WA      36     0     8
  [36] .dynstr           STRTAB           0000000000008000  00008000
       00000000000000e8  0000000000000000   A       0     0     8
  [37] .interp           PROGBITS         0000000000009000  00009000
       0000000000000025  0000000000000000   A       0     0     8
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

