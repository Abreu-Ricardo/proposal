#!/bin/bash

set -o pipefail

string="$1"

if [ "$string" = "up" ]; then
ip netns add servidor; 
ip netns add r1; 
ip netns add n3; 
ip netns add n4; 

# Servidor --> R1
# 10.10.1.1 --> 192.168.1.2
#sudo ip link add veth1 type veth peer name veth2; 
sudo ip link add veth1 netns servidor type veth peer name veth2 netns r1;

# R1 --> N3
# 10.10.2.3 --> 192.168.2.4
#sudo ip link add veth3 type veth peer name veth4;
sudo ip link add veth3 netns r1 type veth peer name veth4 netns n3;

# N3 --> N4
# 10.10.3.5 --> 192.168.3.6
#sudo ip link add veth5 type veth peer name veth6;
sudo ip link add veth5 netns n3 type veth peer name veth6 netns n4;


# N4 --> Servidor
# 10.10.4.7 --> 192.168.4.8
#sudo ip link add veth5 type veth peer name veth6;
sudo ip link add veth7 netns n4 type veth peer name veth8 netns servidor;


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
# Servidor
sudo ip netns exec servidor ip addr add 10.10.10.2/24 dev veth1;
sudo ip netns exec servidor ip addr add 40.40.40.3/24 dev veth8;

# R1
sudo ip netns exec r1 ip addr add 10.10.10.1/24 dev veth2;
sudo ip netns exec r1 ip addr add 20.20.20.1/24 dev veth3;

# N3
sudo ip netns exec n3 ip addr add 20.20.20.2/24 dev veth4;
sudo ip netns exec n3 ip addr add 30.30.30.2/24 dev veth5;

# N4
sudo ip netns exec n4 ip addr add 30.30.30.3/24 dev veth6;
sudo ip netns exec n4 ip addr add 40.40.40.2/24 dev veth7;


# Levantando os loopbacks e as veths 
sudo ip netns exec servidor ip link set lo up;
sudo ip netns exec servidor ip link set dev veth1 up;
sudo ip netns exec servidor ip link set dev veth8 up;

sudo ip netns exec r1 ip link set lo up;
sudo ip netns exec r1 ip link set dev veth2 up;
sudo ip netns exec r1 ip link set dev veth3 up;

sudo ip netns exec n3 ip link set lo up;
sudo ip netns exec n3 ip link set dev veth4 up;
sudo ip netns exec n3 ip link set dev veth5 up;

sudo ip netns exec n4 ip link set lo up;
sudo ip netns exec n4 ip link set dev veth6 up;
sudo ip netns exec n4 ip link set dev veth7 up;


# Habilitando o roteamento nos containers
bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';

sudo ip netns exec servidor sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
sudo ip netns exec r1 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
sudo ip netns exec n3 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; 
sudo ip netns exec n4 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; 

# Desligando o reverse path filtering das interfaces
sudo ip netns exec servidor sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth8/rp_filter'
sudo ip netns exec r1       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth2/rp_filter'
sudo ip netns exec r1       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth3/rp_filter'
sudo ip netns exec n3       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth4/rp_filter'
sudo ip netns exec n3       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth5/rp_filter'
sudo ip netns exec n4       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth6/rp_filter'
sudo ip netns exec n4       sh -c 'echo 0 >  /proc/sys/net/ipv4/conf/veth7/rp_filter'


## 0.0.0.0 --> Sinaliza para como gateway padrao
# Rotear pelo R1: Servidor --> R1 --> N3
#                       N3 --> R1 --> Servidor
sudo ip netns exec servidor sh -c 'route add -net 0.0.0.0/0 gw 10.10.10.1 ';  
sudo ip netns exec       n3 sh -c 'route add -net 0.0.0.0/0 gw 20.20.20.1 '; 


# Rotear pelo N4: Servidor --> N4 --> N3
#                       N3 --> N4 --> Servidor
#sudo ip netns exec servidor sh -c 'route add -net 0.0.0.0/0 gw 40.40.40.2 ';  
#sudo ip netns exec       n3 sh -c 'route add -net 0.0.0.0/0 gw 30.30.30.3 '; 






#sudo ip netns exec n3 sh -c 'ethtool -K veth4 gro on' 
#sudo ip netns exec n3 sh -c 'ethtool -K veth5 gro on' 

echo "Servidor--> sudo ip netns exec servidor bash";
echo "R1--> sudo ip netns exec r1 bash";
echo "N3--> sudo ip netns exec n3 bash";
echo "N4--> sudo ip netns exec n4 bash";

# Precisa passar o nome da veth para poder pingar
# Se nao, vai usar a veth que n tem par com a outra veth
echo " "
echo " "
echo "Para pingar--> ping 10.10.10.* -c 3 -I <nome_veth>"



#sudo ip netns exec n1 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
#sudo ip netns exec n2 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  
#sudo ip netns exec n3 sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward';  

fi
######################################

######################################
if [ "$1" == "down" ]; then

ip netns delete servidor;  #server
ip netns delete r1;  #client
ip netns delete n3;  #host
ip netns delete n4;  #host



bash -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'

fi
