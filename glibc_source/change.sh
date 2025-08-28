#!/bin/sh

# This script is used to change the default libc library to the one specified using patchelf
# libc and ld file in glibcs/ld-${version}.so

# param1: filename
# param2: version of libc

# root directary using store libc and ld
root_dir=/home/glibc_source/glibcs



# if param is not 2, print help
if [ $# -ne 2 ]; then
    # print banner and help and author selph
    echo "Change libc to the specified version"
    echo "Usage: $0 [filename] [version]"
    echo "Example: $0 a.out 2.35"
    echo "Author: selph"  
    exit 1
fi

# recvice a param named filename and version
filename=$1
version=$2

# patchelf change file's ld 
patchelf --set-interpreter ${root_dir}/ld-${version}.so $filename
# patchelf change file's libc
patchelf --replace-needed libc.so.6 ${root_dir}/libc-${version}.so $filename
