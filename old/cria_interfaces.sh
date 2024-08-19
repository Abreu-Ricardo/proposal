#!/bin/bash
# Cria interfaces virtuais com 4 filas de recepção
ip link add dev eth0 numrxqueues 4 numtxqueues 4 type veth peer name eth1 numrxqueues 4 numtxqueues 4

# Cria os network namespaces (hosts)
ip netns add server
ip netns add client

# Move as interfaces para os namespaces
ip link set eth0 netns server
ip link set eth1 netns client

# Configura os endereços IPs e ativa as interfaces de rede
ip netns exec server ifconfig eth0 10.10.10.1 netmask 255.255.255.0 up
ip netns exec server ifconfig lo up

ip netns exec client ifconfig eth1 10.10.10.2 netmask 255.255.255.0 up
ip netns exec client ifconfig lo up

#ip netns exec iperf3 -s > /dev/null 2> /dev/null &

