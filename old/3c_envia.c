/* Objetivo: Container2 altera o IP de destino do pacote para o container3. 

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
#include <linux/icmp.h>
/****************IP's DO TESTE DE CONTAINERS EM TRIANGULO*****************/
// IP local da minha maquina em decimal 192.168.0.20 --> 0x0c0a80014 em hexadecimal
// IP do container1  veth1/192.168.1.1 --> 0x0c0a80101   veth6/192.168.3.6 --> 0x0c0a80306
// IP do container2  veth2/192.168.1.2 --> 0x0c0a80102   veth3/192.168.2.3 --> 0x0c0a80203
// IP do container3  veth4/192.168.2.4 --> 0x0c0a80204   veth5/192.168.3.5 --> 0x0c0a80305
#define IP_C1v1   0x0c0a80101   // IP do container1 que veth1 envia 
#define IP_C1v6   0x0c0a80306   // IP do container1 que veth6 recebe
#define IP_C2v2   0x0c0a80102   // IP do container2 que veth2 recebe
#define IP_C2v3   0x0c0a80203   // IP do container2 que veth3 envia
#define IP_C3v4   0x0c0a80204   // IP do container3 que veth4 recebe
#define IP_C3v5   0x0c0a80305   // IP do container3 que veth5 envia


/****************IP's DO TESTE DE CONTAINERS COM BRIDGE*****************/
// IP container1 --> 10.100.0.10 --> 0x0a640001 
// IP container2 --> 10.100.0.20 --> 0x0a640014 
// IP container3 --> 10.100.0.30 --> 0x0a64001e 
#define IP_C1 0x0a64000a
#define IP_C2 0x0a640014
#define IP_C3 0x0a64001e

// Para pegar o ifindex --> sudo cat /sys/class/net/INTERFACE/ifindex



struct icmphdr_common {
	__u8		type;
	__u8		code;
	__sum16	cksum;
};



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
			//bpf_printk("3c_envia: saddr:%x daddr:%x\n", bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));
		}
	}
	return protocol;
}

/***********************************************************************************************/
// fold_helper do ip
static __always_inline __u16 csum_fold_helper_ip(__u64 csum){
    
    int i;

    // O checksum do ip calcula o complemento de 1 da soma de todos os 16 bits do cabecalho
    #pragma unroll
    for (i = 0; i < 4; i++){
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }

    return ~csum;   
} 

static __always_inline __u16 iph_sum(struct iphdr *iph){
    
    iph->check = 0;
    
    unsigned long long csum = bpf_csum_diff( 0 , 0 , (unsigned int *)iph, sizeof(struct iphdr), 0);
    bpf_printk("3c_recebe: iph csum--> %lld\n", csum);
    
    return csum_fold_helper_ip(csum);
}

/***********************************************************************************************/
// fold_helper do icmp
static __always_inline __u16 csum_fold_helper(__u32 csum){
    
    __u32 sum;
    
    sum  = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static __always_inline __u16 icmp_sum( struct icmphdr *icmp){
    
    unsigned long long csum = 0;
    
    csum = bpf_csum_diff( 0 , 0 , (__be32 *)icmp, sizeof(struct icmphdr_common), 0);
    bpf_printk("3c_recebe: icmp csum--> %lld\n", csum);
    
    return csum_fold_helper(csum);
}

/***********************************************************************************************/

static __always_inline int verifica_ip(struct __sk_buff *ctx){

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
    unsigned int *crc = (unsigned int *)data_end;

    //bpf_printk("DATAS: %p %p \n", data, data_end);

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
		return 1;
	}

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){
		struct iphdr *iph = data + sizeof(struct ethhdr);
		
		if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){

			if ( bpf_ntohl(iph->daddr) == IP_C1v1 ){
                struct icmphdr *icmp = data;
            
                if ( data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) <= data_end ){

                    // MAC Container1
                    // veth3 do C2 --> fe:53:33:bc:b0:4d 
                    eth->h_source[0] = 0xfe;
                    eth->h_source[1] = 0x53;
                    eth->h_source[2] = 0x33;
                    eth->h_source[3] = 0xbc;
                    eth->h_source[4] = 0xb0;
                    eth->h_source[5] = 0x4d;


                    // Altera o enderco MAC de destino do pacote para o veth4 do container3 
                    // 12:57:58:8f:c2:e0 
                    eth->h_dest[0] = 0x12;
                    eth->h_dest[1] = 0x57;
                    eth->h_dest[2] = 0x58;
                    eth->h_dest[3] = 0x8f;
                    eth->h_dest[4] = 0xc2;
                    eth->h_dest[5] = 0xe0;
                    

                    // Altera o IP destino do pacote para o IP do container3	
                    iph->saddr = bpf_htonl(IP_C2v3);
                    iph->daddr = bpf_htonl(IP_C3v4);
                    
                    iph->check     = iph_sum(iph);
                    //struct icmphdr_common *icmp_old, *icmp_new;
                    //icmp->checksum = icmp_sum(icmp);

                    
                    // iph->tot_len eh total em bytes do datagram inteiro, subtraia os campos ja alocados
                    __u32 tam =  iph->tot_len ;
                    bpf_printk("3c_envia: iph->total_legth: %d \n", bpf_ntohs(iph->tot_len));

                    return 0;  // IP destino eh o esperado
                }
            }
		}
	}

	return 1; // IP  destino n eh o esperado
}



SEC("tc")
int redireciona_pacotes(struct __sk_buff *ctx ){

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("DATAS: %p %p \n", data, data_end);
    bpf_printk("DATAS2: %lu %lu\n",  data, data_end);
    
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
                //bpf_printk("change_ip: ip_ret:%d Redirecionando...\n", ip_ret);
            }
            // Redireciona msm sem o redirect
            redir = bpf_redirect( /*ctx->ifindex*/ 3 , /*BPF_F_INGRESS*/ 0 );
            //redir = bpf_clone_redirect(ctx, ctx->ifindex, BPF_F_INGRESS);
        
            if (redir == 7){
                bpf_printk("3c_envia: redir-->%d\n", redir);
            }
            else {
                bpf_printk("3c_envia: redir N EH REDIRECT-->%d\n", redir);
            }
            
        }
    }

    // Valor 7 em redir, significa TC_ACT_REDIRECT, de acordo com pkt_cls.h
	return redir; 
	//return TC_ACT_OK;
}


char _license[] SEC("license") = "GPL";


