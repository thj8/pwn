CC = gcc
CFLAGS = -m32 -static -pie -fstack-protector

all: arbitrary

arbitrary: arbitrary.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f arbitrary