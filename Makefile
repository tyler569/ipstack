
.PHONY: all

SRC= net.c list.c

TARGET= net

CFLAGS= -Wall -Wno-address-of-packed-member -g

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^
