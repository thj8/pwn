#!/bin/sh

# a function to show usage info
usage() {
    # highlight print the usage and author
    echo "\033[31mUsage:    $0 [version]\033[0m"
    echo "Example:  $0 2.35"
    echo "Author:   selph"
    exit 1
}
# param check 
if [ $# -ne 1 ]; then
    usage
fi

# if param is -h or --help, show usage info
if [ $1 = "-h" ] || [ $1 = "--help" ]; then
    usage
fi

# check if install, if not install it
sudo apt install vim gcc make python3 gawk bison texinfo gettext wget


# recvice a param named version
version=$1

# split version to url
url="https://ftp.gnu.org/gnu/glibc/glibc-${version}.tar.gz"

# judge the file is exist or not, if not download it
if [ ! -f "glibc-${version}.tar.gz" ]; then
    mget $url
fi

# uncompress the file
tar -zxvf glibc-${version}.tar.gz

# create build and out dir
mkdir glibc-${version}_build
mkdir glibc-${version}_out

# get prefix path
prefix=$(pwd)/glibc-${version}_out
# enter build dir and compile
cd glibc-${version}_build
../glibc-${version}/configure --prefix=$prefix CFLAGS="-Og -g -g3 -ggdb -gdwarf-4" CXXFLAGS="-Og -g -g3 -ggdb -gdwarf-4" --disable-werror
make -j12
# make install

# exit build dir
cd ..

# check glibcs dir is exist or not, if not create it
if [ ! -d "glibcs" ]; then
    mkdir glibcs
fi

# make a another dir to store all libc's libc.so and ld.so
#cp glibc-${version}_out/lib/libc.so.6 glibcs/libc-${version}.so
#cp glibc-${version}_out/lib/ld-linux-x86-64.so.2 glibcs/ld-${version}.so
 
# libc.so 就在glibc-2.xx_build目录下
# ld.so 就在glibc-2.xx_build/elf 目录下
# copy libc.so and ld.so to glibcs dir
cp glibc-${version}_build/libc.so glibcs/libc-${version}.so
cp glibc-${version}_build/elf/ld.so glibcs/ld-${version}.so

# check if have trash-cli ,if not using rm command
if [ ! -x "$(command -v trash)" ]; then
    rm -rf glibc-${version}_build
else
    # remove build dir
    trash glibc-${version}_build
    # clear trash
    trash-empty
fi
