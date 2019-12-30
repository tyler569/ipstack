
.PHONY: all

all: main.c Makefile
	cc -Wall -Wno-address-of-packed-member main.c -o net
