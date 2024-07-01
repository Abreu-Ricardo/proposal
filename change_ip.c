/* Objetivo: Alterar o IP de destino do pacote. 

*/
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <bpf/bpf_endian.h> // bpf_ntohl()
#include <stdlib.h>


// IP local da minha maquina em decimal 192.168.0.20 --> 0x0c0a80014 em hexadecimal
// IP do container1  10.100.0.10 --> 0x0a64000a
// IP do container2  10.100.0.20 --> 0x0a640014

#define IP_HOST 0x0c0a80014 // IP local host 192.168.0.20
#define IP_C1   0x0a64000a  // container 1
#define IP_C2   0x0a640014  // container 2
#define IP_BR   0x0a640001  // IP bridge



// Para pegar o ifindex --> sudo cat /sys/class/net/INTERFACE/ifindex

// MAP
struct{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64); 
//	__uint(pinning, LIBBPF_PIN_BY_NAME);   
} pkt_send SEC(".maps");


static __always_inline unsigned char lookup_protocol(struct __sk_buff *ctx){
	unsigned char protocol = 0;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
		return 0;
	}
	

	// Verificar se eh um pacote IP
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){
		// Protocolo do pacote
		// 1 = ICMP
		// 6 = TCP
		// 17 = UDP

		struct iphdr *iph = data + sizeof(struct ethhdr);
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
			protocol = iph->protocol;
			//bpf_printk("change_ip: saddr:%x daddr:%x\n", bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));
		}
	}
	return protocol;
}


static __always_inline int verifica_ip(struct __sk_buff *ctx){

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
		return 1;
	}

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){
		struct iphdr *iph = data + sizeof(struct ethhdr);
		
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){

			/* PERGUNTA--> o saddr imprime a64000a/IP_C1
			   PERGUNTA--> e o daddr imprime a640001/IP_BR */
			// Como o programa eh um programa TC, ja foi processado pela network stack, 
			// entao os enderecos IP já foram alterados
			if ( bpf_ntohl(iph->daddr) == IP_BR ){ 
				// Altera o enderco MAC de destino do pacote para o container 2
				eth->h_dest[0] = 0x26;
				eth->h_dest[1] = 0x4a;
				eth->h_dest[2] = 0x13;
				eth->h_dest[3] = 0x03;
				eth->h_dest[4] = 0x01;
				eth->h_dest[5] = 0x70;
				
				//bpf_printk("DEU CERTO A COMPARACAO \n");
				
                // Altera o IP destino do pacote para o IP do container2	
				iph->daddr = bpf_htonl(IP_C2);
			    
                //bpf_printk("change_ip: saddr:%x daddr:%x\n", bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));
				
                return 0;  // IP destino eh o esperado
			}

		}
	}

	return 1; // IP  destino n eh o esperado
}



SEC("tc")
int redireciona_pacotes(struct __sk_buff *ctx ){
	__u32 key = 0;
	__u64 protocolo = lookup_protocol(ctx);
	__u64 *count;

	__u32 ip_ret = verifica_ip(ctx);
	__u32 redir = 0;

	// Filtra pacotes de acordo com o protocolo
    if (ip_ret == 0){
        if ( protocolo  == 1){

            count = bpf_map_lookup_elem(&pkt_send, &key);
            if (count != NULL){
                (*count)++;
                //bpf_printk("Pacotes--> %d\n", *count);
                bpf_printk("change_ip: Redirecionando...\n");
            }
            // Redireciona msm sem o redirect
            // redir = bpf_redirect( ctx->ifindex, BPF_F_INGRESS );
            // redir = bpf_clone_redirect(ctx, ctx->ifindex, BPF_F_INGRESS);
        }
    }
    /*
    else{
        if ( protocolo  == 1 ){
            bpf_printk("Recebendo pacote que n eh da BRIDGE\n");
        }
    }
    */

	// return redir; // Com redir de bpf_redirect ele n envia para container2
	return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
