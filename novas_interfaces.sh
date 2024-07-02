#!/bin/bash

set -o pipefail

string="$1"

if [ "$string" = "up" ]; then
ip netns add n1; 
ip netns add n2; 
ip netns add n3; 


# N1 --> N2
#sudo ip link add veth1 type veth peer name veth2;
sudo ip link add veth1 netns n1 type veth peer name veth2 netns n2;

# N2 --> N3
#sudo ip link add veth3 type veth peer name veth4;
sudo ip link add veth3 netns n2 type veth peer name veth4 netns n3;

# N3 --> N1
#sudo ip link add veth5 type veth peer name veth6;
sudo ip link add veth5 netns n3 type veth peer name veth6 netns n1;

#####################################################

# Movendo as veth para os netspaces
# N1 --> veth1 e veth6 
# N1 <---> N2
# N1 <--_> N3                         
#sudo ip link set veth1 netns n1;
#sudo ip link set veth6 netns n1;
#
## N2 --> veth 2 e veth3
## N2 <---> N1 
## N2 <---> N3          
#sudo ip link set veth2 netns n2;
#sudo ip link set veth3 netns n2;
#
## N3 --> veth4 e veth 5
## N3 <---> N1 
## N3 <---> N2
#sudo ip link set veth4 netns n3;
#sudo ip link set veth5 netns n3;


# Atribuindo IP para cada veth
# N1
sudo ip netns exec n1 ip addr add 192.168.1.1/24 dev veth1;
sudo ip netns exec n1 ip addr add 192.168.1.6/24 dev veth6;

# N2
sudo ip netns exec n2 ip addr add 192.168.1.2/24 dev veth2;
sudo ip netns exec n2 ip addr add 192.168.1.3/24 dev veth3;

# N3
sudo ip netns exec n3 ip addr add 192.168.1.4/24 dev veth4;
sudo ip netns exec n3 ip addr add 192.168.1.5/24 dev veth5;


# Levantando os loopbacks e as veths 
sudo ip netns exec n1 ip link set lo up;
sudo ip netns exec n1 ip link set dev veth1 up;
sudo ip netns exec n1 ip link set dev veth6 up;

sudo ip netns exec n2 ip link set lo up;
sudo ip netns exec n2 ip link set dev veth2 up;
sudo ip netns exec n2 ip link set dev veth3 up;

sudo ip netns exec n3 ip link set lo up;
sudo ip netns exec n3 ip link set dev veth4 up;
sudo ip netns exec n3 ip link set dev veth5 up;

bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';

sudo ip netns exec n1 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
sudo ip netns exec n2 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
sudo ip netns exec n3 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; 



echo "N1--> sudo ip netns exec n1 bash";
echo "N2--> sudo ip netns exec n2 bash";
echo "N3--> sudo ip netns exec n3 bash";

# Precisa passar o nome da veth para poder pingar
# Se nao, vai usar a veth que n tem par com a outra veth
echo " "
echo " "
echo "Para pingar--> ping 192.168.1.* -c 3 -I <nome_veth>"



#sudo ip netns exec n1 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
#sudo ip netns exec n2 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
#sudo ip netns exec n3 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  

fi
######################################

######################################
if [ "$1" == "down" ]; then

ip netns delete n1;  #server
ip netns delete n2;  #client
ip netns delete n3;  #host


#ip link delete veth1 #veth1
#ip link delete veth2 #veth2
#ip link delete veth3 #veth3
#ip link delete veth4 #veth3
#ip link delete veth5 #veth3
#ip link delete veth6 #veth3

#ip link delete br00

bash -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'

fi
