patchelf --set-interpreter ./ld-2.31.so ./vuln
patchelf --replace-needed libc.so.6 ./libc.so.6  ./vuln
