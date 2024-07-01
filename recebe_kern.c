#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <bpf/bpf_endian.h> // bpf_ntohs()

/* Enderecos MAC
 * vth1:
 * 0xd6
 * 0xc6
 * 0x9f
 * 0xbc
 * 0xce
 * 0x8c
 *
 * vth2:
 * 0x26
 * 0x4a
 * 0x13
 * 0x03
 * 0x01
 * 0x70
 *
 * PC:
 * 0xb4
 * 0x2e
 * 0x99
 * 0xc5
 * 0xc5
 * 0x8c
 *
 * BR:
 * 0x82
 * 0x1d
 * 0xcd
 * 0x6f
 * 0x6b
 * 0x6c
 *
 * */




#define IP_HOST 0x0c0a80014 // IP local host 192.168.0.20
#define IP_C1   0x0a64000a  // container 1
#define IP_C2   0x0a640014  // container 2
#define IP_BR   0x0a640001  // IP bridge

// MAP
struct{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);    
} pkt_counter SEC(".maps");



static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx){
	unsigned char protocol = 0;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

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
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
			protocol = iph->protocol;
			//bpf_printk("--- %x\n", bpf_ntohl(iph->saddr ));
		}
	}
	return protocol;
}

// Verifica se IP de origem eh o IP do container1
static __always_inline int verifica_ip(struct xdp_md *ctx){

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
		return 1;
	}

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){	
		struct iphdr *iph = data + sizeof(struct ethhdr);
		
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
			
			if ( bpf_ntohl(iph->saddr) == IP_C1 ){
				return 0;  // IP destino eh o esperado
			}
		}
	}
	return 1; // IP  destino n eh o esperado
}

// Altera cabecalho do pacote para redirecionar 
static __always_inline void altera_ip(struct xdp_md *ctx){
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
        return;
    }

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){	
		struct iphdr *iph = data + sizeof(struct ethhdr);
		
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
			
			if ( bpf_ntohl(iph->saddr) == IP_C1 ){

                // MAC Container1
    	/*	    
                eth->h_source[0] = 0xd6;
				eth->h_source[1] = 0xc6;
				eth->h_source[2] = 0x9f;
				eth->h_source[3] = 0xbc;
				eth->h_source[4] = 0xce;
				eth->h_source[5] = 0x8c;
          */      

                // MAC Container2
                bpf_printk("recebeKern-->h_source: %x %x %x ", eth->h_source[0], eth->h_source[1], eth->h_source[2]);
                bpf_printk("%x %x %x\n", eth->h_source[3], eth->h_source[4], eth->h_source[5]);
                
                // MAC SOURCE
                eth->h_source[0] = 0x26;
				eth->h_source[1] = 0x4a;
				eth->h_source[2] = 0x13;
				eth->h_source[3] = 0x03;
				eth->h_source[4] = 0x01;
				eth->h_source[5] = 0x70;
                

                // MAC DEST
                eth->h_dest[0] = 0xd6 ;
				eth->h_dest[1] = 0xc6 ;
				eth->h_dest[2] = 0x9f ;
				eth->h_dest[3] = 0xbc ;
				eth->h_dest[4] = 0xce ;
				eth->h_dest[5] = 0x8c ;

				iph->saddr = bpf_htonl(IP_C2);
                iph->daddr = bpf_htonl(IP_C1);

				//bpf_printk("recebe_kern: daddr:%x saddr:%x\n", bpf_ntohl(iph->daddr), bpf_ntohl(iph->saddr));
				return;  // IP destino eh o esperado
			}
		}
	}
}


// CODE XDP
SEC("xdp")
int recebe_pacotes(struct xdp_md *ctx ){
	__u32 key = 0;
	__u64 protocolo = lookup_protocol(ctx);
	__u64 *count;

    __u32 redir = 0;
	__u32 ip_ret = verifica_ip(ctx);

	//TODO
	// Redirecionar o pacote para o host para que os programas continuem a funcionar, ping e iperf3
    
    //TODO
    // NAO TA DANDO CERTO POR CAUSA DO IPTABLES, OS PACOTES QUE VAO PARA O HOST ESTAO SENDO DROPADOS OU RESPONDIDOS PELA BRIDGE

	
	// Filtra pacotes 
	if ( ip_ret == 0  ){ // Se pacote do IP do container1
		if (protocolo == 1){ // Filtra pacotes
			count = bpf_map_lookup_elem(&pkt_counter, &key);
			
			if (count != NULL){
				(*count)++;
				bpf_printk("recebe_kern: %d ret:%d\n", *count, ip_ret);
			}

            altera_ip(ctx);
		}

        redir = bpf_redirect( ctx->ingress_ifindex, BPF_F_INGRESS );
	}
    

	return XDP_TX;
	//return XDP_PASS;
	//return redir;
}

char _license[] SEC("license") = "GPL";

