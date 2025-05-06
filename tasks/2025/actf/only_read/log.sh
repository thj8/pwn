#!/bin/bash

python3 /proof-of-work.py && timeout -k 5 30 /usr/sbin/chroot --userspec=1000:1000 /home/ctf /app 2>/dev/null
