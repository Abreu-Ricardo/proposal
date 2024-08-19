#!/bin/bash

set -o pipefail

string="$1"

if [ "$string" = "up" ]; then
ip netns add server
ip netns add client

ip link add veth1 type veth peer name vethpeer1
ip link add veth2 type veth peer name vethpeer2

ip link set veth1 up
ip link set veth2 up

ip link set vethpeer1 netns server
ip link set vethpeer2 netns client

ip netns exec server ip link set lo up
ip netns exec client ip link set lo up
ip netns exec server ip link set vethpeer1 up
ip netns exec client ip link set vethpeer2 up

ip netns exec server ip addr add 10.100.0.10/16 dev vethpeer1
ip netns exec client ip addr add 10.100.0.20/16 dev vethpeer2

ip link add br00 type bridge
ip link set br00 up

ip link set veth1 master br00
ip link set veth2 master br00

ip addr add 10.100.0.1/16 dev br00

ip netns exec server ip route add default via 10.100.0.1
ip netns exec client ip route add default via 10.100.0.1

ip netns exec server ping -c 3 10.100.0.20

ip netns exec client ping -c 3 10.100.0.10


echo ""
echo ""
echo "Enabling ip_forwarding ...."
echo ""

sleep 2

bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

#iptables -t nat -A POSTROUTING -s 10.100.0.1/16 ! -o br00 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.100.0.1/16  -o br00 #-j MASQUERADE


echo ""
echo "Ping Google DNS....."
echo ""
sleep 2

ip netns exec server ping -c 3 8.8.8.8

fi



if [ "$1" == "down" ]; then

ip netns delete server
ip netns delete client

ip link delete br00

bash -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'

fi
