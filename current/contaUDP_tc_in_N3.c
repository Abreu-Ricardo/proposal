#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <linux/in.h>
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <linux/icmp.h>
#include <bpf/bpf_endian.h> // bpf_ntohs()
#include <stddef.h>


/****************IP's DO TESTE DE CONTAINERS EM TRIANGULO*****************/
// IP local da minha maquina em decimal 192.168.0.20 --> 0x0c0a80014 em hexadecimal
// IP do container1  veth1/192.168.1.1 --> 0x0c0a80101   veth6/192.168.3.6 --> 0x0c0a80306
// IP do container2  veth2/192.168.1.2 --> 0x0c0a80102   veth3/192.168.2.3 --> 0x0c0a80203
// IP do container3  veth4/192.168.2.4 --> 0x0c0a80204   veth5/192.168.3.5 --> 0x0c0a80305

//#define IP_C1v1   0x0c0a80101   // IP do container1 que veth1 envia 
//#define IP_C1v6   0x0c0a80306   // IP do container1 que veth6 recebe
//#define IP_C2v2   0x0c0a80102   // IP do container2 que veth2 recebe
//#define IP_C2v3   0x0c0a80203   // IP do container2 que veth3 envia
//#define IP_C3v4   0x0c0a80204   // IP do container3 que veth4 recebe
//#define IP_C3v5   0x0c0a80305   // IP do container3 que veth5 envia


/****************IP's DO TESTE DE CONTAINERS COM BRIDGE*****************/
// IP container1 --> 10.100.0.10 --> 0x0a64000a 
// IP container2 --> 10.100.0.20 --> 0x0a640014 
// IP container3 --> 10.100.0.30 --> 0x0a64001e 
//#define IP_C1 0x0a64000a
//#define IP_C2 0x0a640014
//#define IP_C3 0x0a64001e



/******* IP dos containers do experimento *******/
#define IP_Sv1   0x0a0a0a02  // 10.10.10.2
#define IP_Sv8   0x028282803 // 40.40.40.3

#define IP_R1v2  0x0a0a0a01  // 10.10.10.1
#define IP_R1v3  0x014141401 // 20.20.20.1

#define IP_N3v4  0x014141402 // 20.20.20.2
#define IP_N3v5  0x01e1e1e02 // 30.30.30.2

#define IP_N4v6  0x01e1e1e03 // 30.30.30.3
#define IP_N4v7  0x028282802 // 40.40.40.2


// MAP
struct{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);    
} contador_UDP SEC(".maps");


/***********************************************************************************************/
static __always_inline unsigned char lookup_protocol(struct __sk_buff *ctx){
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
			//bpf_printk("3c_recebe: saddr:%x daddr:%x\n", bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));		
        }
	}
	return protocol;
}

/***********************************************************************************************/
// 
static __always_inline int verifica_ip(struct __sk_buff *ctx){

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
		return -1; // IP  destino n eh o esperado
	}

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){	
		struct iphdr *iph = data + sizeof(struct ethhdr);
		
        if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
			if ( bpf_ntohl(iph->daddr) ==  IP_N3v4)
				return 0;  // IP destino eh o esperado
          
		}
	}
	return -1; // IP  destino n eh o esperado
}

/***********************************************************************************************/
// fold_helper do ip
static __always_inline __u16 csum_fold_helper_ip(__u64 csum){
    
    int i;

    // checksum do ip: calcula o complemento de 1 da soma de todos os 16 bits do cabecalho
    #pragma unroll
    for (i = 0; i < 4; i++){
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }

    return ~csum;   
} 

/***********************************************************************************************/
static __always_inline __u16 iph_sum(struct iphdr *iph){
    
    iph->check = 0;
    
    unsigned long long csum = bpf_csum_diff( 0 , 0 , (unsigned int *)iph, sizeof(struct iphdr), 0);
    //bpf_printk("3c_recebe: iph csum--> %lld\n", csum);
    
    return csum_fold_helper_ip(csum);
}
/***********************************************************************************************/
// Altera cabecalho do pacote para redirecionar 
static __always_inline void altera_ip(struct __sk_buff *ctx){
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
        return;
    }

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){	
		struct iphdr *iph = data + sizeof(struct ethhdr);
		
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
           // struct icmphdr *icmp = data + sizeof(struct iphdr);
            
            //if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) <= data_end ){ 
                // MAC da veth7 do Container4
                // ea:09:c5:82:35:ec 
                //eth->h_source[0] = 0xea;
                //eth->h_source[1] = 0x09;
                //eth->h_source[2] = 0xc5;
                //eth->h_source[3] = 0x82;
                //eth->h_source[4] = 0x35;
                //eth->h_source[5] = 0xec;


                // MAC DEST veth8 do servidor
                // de:db:8e:6e:ca:c1 
                //eth->h_dest[0] = 0xde;
                //eth->h_dest[1] = 0xdb;
                //eth->h_dest[2] = 0x8e;
                //eth->h_dest[3] = 0x6e;
                //eth->h_dest[4] = 0xca;
                //eth->h_dest[5] = 0xc1;

                // Se colocar IP da veth5 o ping aponta (DIFFERENT ADDRESS!), mas funciona
                
                // Com ip destino real, veth2 o ping funciona normal, sem msg nem erros
				//iph->saddr = bpf_htonl(IP_C2v2);
				//iph->saddr = bpf_htonl(IP_C3v5); 
                //iph->daddr = bpf_htonl(IP_C1v6);
                //iph->check     = iph_sum(iph);


                //bpf_printk("3c_recebe2--> icmp.type %d icmp.code %d\n", bpf_ntohs(icmp->type), bpf_ntohs(icmp->code) );
				//bpf_printk("***3c_recebe: daddr:%x saddr:%x\n", bpf_ntohl(iph->daddr), bpf_ntohl(iph->saddr));
				return;  // IP destino eh o esperado
            //}
		}
	}
}


/***********************************************************************************************/
// CODE TC ingress
SEC("tc")
int tc_recebe_pacotes(struct __sk_buff *ctx ){
	__u32 key = 0;
	__u64 protocolo = lookup_protocol(ctx);
	__u64 *count;

    __u32 redir = 0;
	__u32 ip_ret = verifica_ip(ctx);




	// TODO
	// Redirecionar o pacote para o host para que os programas continuem a funcionar, ping e iperf3
    
	
	// Filtra pacotes 
    if ( protocolo  == 17  ||  protocolo  == 6 ){ // Se pacote do IP do container2
    //if ( protocolo  == 1 ){ // Se pacote do IP do container2
        if ( ip_ret == 0 && protocolo == 17 ){ // Filtra pacotes

            count = bpf_map_lookup_elem(&contador_UDP, &key);

            if (count != NULL){
                (*count)++;
                //bpf_printk("recebe_kern: %d ret:%d\n", *count, ip_ret);
            }
        }
        //altera_ip(ctx);
                                 // (INDEX DA INTERFACE , CODIGO BPF_F_INGRESS ou 0)
        //return bpf_redirect( /*ctx->ingress_ifindex*/ 3 , /*BPF_F_INGRESS*/ 0 ); 
    }
 
    //bpf_printk("3c_recebe--> redir:%d  cont: %d\n", redir, XDP_ABORTED);
    //bpf_printk("3c_recebe2--> ingress:%d  \n", ctx->ingress_ifindex);

    //return bpf_redirect( /*ctx->ingress_ifindex*/ 3 , /*BPF_F_INGRESS*/ 0 ); 
	return TC_ACT_OK;
    //return XDP_TX;
	//return redir; // Se der certo retorna um XDP_REDIRECT(valor 4) senao XDP_ABORTED(valor 0)
}

char _license[] SEC("license") = "GPL";
