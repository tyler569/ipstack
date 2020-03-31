# ipstack

An IP stack built on raw Ethernet frames from a Linux tap interface.

ipstack provides a Berkely-sockets like interface, where the standard functions are prefixed with an `i_` to indicate to use the ipstack-provided functions.

There are several example programs provided to showcase ipstack's abilities:
- `i_udp_echo.c` is a UDP echo server, mirroring `udp_echo.c`
- `i_tcp_out.c` sends TCP information, mirroring `tcp_out.c`

The intent is that the `i_example.c` files are as close as possible to the `example.c` files, except that the `i_` versions use my IP stack and sockets implementation, while the non-`i_` versions use the system.
