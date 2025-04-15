gcc -fPIC -shared -o zerodays.so zerodays.c
gcc chall.c -o chall -Wl,-rpath=. -L. -l:zerodays.so -lseccomp -no-pie -fno-stack-protector
