#!/bin/sh

sudo ip tuntap add tap0 mode tap
sudo ip link set dev tap0 up
sudo ip addr add 10.50.1.1/24 dev tap0

