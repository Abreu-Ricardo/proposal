#!/bin/bash

set -o pipefail

string="$1"

if [ "$string" = "up" ]; then
ip netns add n1
ip netns add n2
ip netns add n3


ip link add veth1 type veth peer name vethpeer1
ip link add veth2 type veth peer name vethpeer2
ip link add veth3 type veth peer name vethpeer3

ip link set veth1 up
ip link set veth2 up
ip link set veth3 up

ip link set vethpeer1 netns n1
ip link set vethpeer2 netns n2
ip link set vethpeer3 netns n3

ip netns exec n1 ip link set lo up
ip netns exec n2 ip link set lo up
ip netns exec n3 ip link set lo up

ip netns exec n1 ip link set vethpeer1 up
ip netns exec n2 ip link set vethpeer2 up
ip netns exec n3 ip link set vethpeer3 up

ip netns exec n1 ip addr add 10.100.0.10/16 dev vethpeer1
ip netns exec n2 ip addr add 10.100.0.20/16 dev vethpeer2
ip netns exec n3 ip addr add 10.100.0.30/16 dev vethpeer3

ip link add br00 type bridge
ip link set br00 up

ip link set veth1 master br00
ip link set veth2 master br00
ip link set veth3 master br00

ip addr add 10.100.0.1/16 dev br00

ip netns exec n1 ip route add default via 10.100.0.1
ip netns exec n2 ip route add default via 10.100.0.1
ip netns exec n3 ip route add default via 10.100.0.1

ip netns exec n1 ping -c 3 10.100.0.20

ip netns exec n2 ping -c 3 10.100.0.10

ip netns exec n3 ping -c 3 10.100.0.10


echo ""
echo ""
echo "Enabling ip_forwarding ...."
echo ""

sleep 2

bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

sudo ip netns exec n1 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
sudo ip netns exec n2 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
sudo ip netns exec n3 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';


#ip netns exec n1 ifconfig vethpeer1 hw ether 3a:83:f2:b0:fb:a3
#ip netns exec n2 ifconfig vethpeer2 hw ether 4a:40:24:0a:ff:fd 
#ip netns exec n3 ifconfig vethpeer3 hw ether 4e:06:28:fd:cb:33 

#iptables -t nat -A POSTROUTING -s 10.100.0.1/16 ! -o br00 -j MASQUERADE
#iptables -t nat -A POSTROUTING -s 10.100.0.1/16  -o br00 #-j MASQUERADE


#echo ""
#echo "Ping Google DNS....."
#echo ""
#sleep 2

ip netns exec n1 ping -c 3 8.8.8.8

echo "sudo ip netns exec n1 bash"
echo "sudo ip netns exec n2 bash"
echo "sudo ip netns exec n3 bash"
fi

############################################################
if [ "$1" == "down" ]; then

ip netns delete n1
ip netns delete n2
ip netns delete n3

ip link delete br00

bash -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'

fi
