#!/bin/bash


# Teste dos parametros
if [ -z $1 ]; then
	echo -e "ERRO! Nao passou o <programa.c> \n $0 <programa_rx.c> <iface> <up/down>";
	exit 1
fi

if [ -z $2 ]; then
	echo -e "ERRO! Nao passou a <interface> \n$0 <programa_rx.c> <iface> <up/down>";
	exit 1
fi

if [ -z $3 ]; then
	echo -e "ERRO! Nao passou <up/down> \n$0 <programa_rx.c> <iface> <up/down>";
	exit 1
fi
########################################

if [ $3 == 'up' ]; then

	name=$1;	
	# Compila codigo .c passado
	clang -g -O2 -target bpf -c $1;

	# Cria sistema de arquivo virtual do bpf
	sudo mount -t bpf none /sys/fs/bpf/;

	# Carrega o programa com o iproute2 
	#sudo ip -force link set dev $2 xdp obj ${1%.c}.o sec xdp
	sudo xdp-loader load $2 ${1%.c}.o; #-m skb;

	# Mostra a lista de programas atual
	sudo bpftool prog show;


	exit 0;
fi

if [ $3 == "down" ]; then

	# Remove o programa
	# sudo ip sudo ip link set $2 xdp off
	sudo xdp-loader unload --all $2;	

	# Tempo para atualizar a lista de programas
	sleep 1;

	# Mostra a lista de programas atual
	sudo bpftool prog show;

	echo -e "\nListando bpffs:"; 
	sudo ls /sys/fs/bpf/;
	sudo rm ${1%.c}.o;



	exit 0;
fi
