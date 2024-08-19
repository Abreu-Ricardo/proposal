/* Objetivo: Código eBPF rodando no espaço do kernel envia uma pacote para a NIC por meio de um hook TC(BPF_PROG_TYPE_SCHED_CLS) 

	1) Como tem como criar um pacote e enviar no eBPF, vamos redirecionar os pacotes que chegam.
	
	2) Testar se dá tudo certo ao enviar um pacote do host para a veth do container.
		* Se der, redirecionar o pacote do host para a container1 e ele envia pa		  ra o container2.

	3) Container1 recebe o pacote do host por XDP e o container1 envia para o container2 que tbm recebe por xdp e imprime.


***Testar com ping. ping: host pinga --> container1 redireciona --> container2 --> imprime



*/
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <bpf/bpf_endian.h> // bpf_ntohs()


// MAP
struct{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, unsigned int);
	__uint(pinning, LIBBPF_PIN_BY_NAME);   
} pkt_counter SEC(".maps");


static __always_inline unsigned char lookup_protocol(struct __sk_buff *skb){
	unsigned char protocol = 0;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return 0;

	// Verificar se eh um pacote IP
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){
		// Protocolo do pacote
		// 1 = ICMP
		// 6 = TCP
		// 17 = UDP

		struct iphdr *iph = data + sizeof(struct ethhdr);
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
			protocol = iph->protocol;
	}
	return protocol;
}



// CODE
SEC("tc")

int envia_pacotes(struct __sk_buff *skb ){
	__u32 key = 0;
	__u64 *count;
	__u64 protocolo = lookup_protocol(skb);
	
	
	if (protocolo == 1){
		count = bpf_map_lookup_elem(&pkt_counter, &key);
		if (count != NULL){
			*count = *count + 1;
			bpf_printk("Pacotes--> %d\n", *count);
		}

	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
