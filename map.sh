#!/bin/bash


if [ -z $1 ]; then
	
	echo -e "Passe o id do mapa...\n$0 <id>";
	exit 1;
fi


sudo bpftool map dump id $1;
