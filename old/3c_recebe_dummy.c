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




SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	return XDP_PASS;
}
