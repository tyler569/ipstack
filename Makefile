
.PHONY: all

SRC= net.c socket.c i_udp_echo.c i_tcp_out.c

TARGET= net

CFLAGS= -Wall -Wno-address-of-packed-member -g

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $^ -lpthread

clean:
	rm net
