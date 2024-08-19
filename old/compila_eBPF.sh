name=$1
# Flag -g é para gerar o BTF, para pinnar o programa precisa do BTF
clang -g -O2 -target bpf -c $name -o ${name%.c}.o;

# Se for carregar com ip pode ou n precisar do BTF, mas como precisamos pinnar
# e por enquanto eh melhor fazer isso por linha de comando. Vamos usar o bpftool,
# para isso eh preciso que a secao do programa seja xdp.

# Para carregar o programa com secao diferente de prog, eh necessario passar o tipo
# ex: sudo ip -force link set dev eno1 xdp obj <programa.o> sec xdp
#sudo ip -force link set dev eno1 xdp obj ${name%.c}.o sec xdp; 

#### CARRREAGAR COM IP DIRETO N TEM COMO ESPECIFICAR O --pin-path do mapa
#### CARREGAR COM xdp-loader
#sudo xdp-loader load eno1 ${name%.c}.o -m skb --pin-path /sys/fs/bpf/ ;
sudo xdp-loader load vethpeer1 ${name%.c}.o ;


# Para pinnar um programa eh preciso ter o sistema montado primeiro.
# Caso nao esteja --> mount -t bpf bpf /sys/fs/bpf/
# Eh preciso carregar com ip ou um loader custom para anexar a uma interface
# Sem isso n vai executar.

# Isso pina o programa n o mapa do programa
#sudo bpftool prog load ${name%.c}.o /sys/fs/bpf/${name%.c};

# PARA PINAR O MAPA DO PROGRAMA
#sudo bpftool map pin name pkt_counter escrevemap_kern.o

sudo bpftool prog show;
sudo ls /sys/fs/bpf/; 

# sudo ip link set dev eno1 xdp off
