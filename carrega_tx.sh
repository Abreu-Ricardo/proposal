#!/bin/bash

# Teste dos parametros
if [ -z $1 ]; then
	echo "ERRO! $0 <programa_tx.c> <iface> <up/down>";
	exit 1
fi

if [ -z $2 ]; then
	echo "ERRO! $0 <programa_tx.c> <iface> <up/down>";
	exit 1
fi

if [ -z $3 ]; then
	echo "ERRO! $0 <programa_tx.c> <iface> <up/down>";
	exit 1
fi

########################################

if [ $3 == 'up' ]; then

	name=$1;	
	# Compila codigo .c passado
	clang -g -O2 -target bpf -c $1;


	# Cria um clsact caso n tenha
	sudo tc qdisc add dev $2 clsact;

	# Carrega o programa
	#tc filter add dev $2 egress bpf object-pinned /sys/fs/bpf/${name%.c};
	#sudo tc filter add dev $2 egress bpf da obj ${name%.c}.o sec tc --pin-path /sys/fs/bpf/${name%.c};
	sudo tc filter add dev $2 egress bpf da obj ${1%.c}.o sec tc;

	sudo bpftool prog show;

	exit 0;
fi

if [ $3 == "down" ]; then

	# Remove o programa
	sudo tc filter del dev $2 egress;
	
	# Remove o clsact
	sudo tc qdisc del dev $2 clsact;

	# Tempo para atualizar a lista de programas
	sleep 1;
	
	# Mostra os programas na NIC
	sudo bpftool prog show;

	rm ${1%.c}.o;
	exit 0;
fi

