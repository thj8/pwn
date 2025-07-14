#!/bin/sh
# Add your startup script
echo "$FLAG" > /home/ctf/flag && \
export FLAG=not && FLAG=not
# DO NOT DELETE
/etc/init.d/xinetd start;
sleep infinity;