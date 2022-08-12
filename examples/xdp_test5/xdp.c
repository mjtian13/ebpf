// +build ignore

//#include "stdio.h"
//#include "string.h"
#include "bpf_endian.h"
#include "common.h"
#include "arpa/inet.h"
#include "linux/in.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16
#define ETH_HLEN 14
#define ETH_P_IPV6 0x86DD

/*
struct in6_addr {
        union {
                __u8            u6_addr8[16];
 #if __UAPI_DEF_IN6_ADDR_ALT
                __be16          u6_addr16[8];
                __be32          u6_addr32[4];
#endif 
        } in6_u;
#define s6_addr                 in6_u.u6_addr8
#define s6_addr16               in6_u.u6_addr16
#define s6_addr32               in6_u.u6_addr32
#endif 
};

// IPv6 Header

struct ipv6hdr {
	__u8			priority:4,
				version:4;
 For Big Endian machine, use it as shown below:
	__u8			version:4,
				priority:4; 

	__u8			flow_lbl[3];
	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;
	struct	in6_addr	saddr;
	struct	in6_addr	daddr;
};

*/
// This is the struct that contains packet info about the packet.
// Can be further expanded to get more details about the packet.

struct packet_info {
	char source_ip[INET6_ADDRSTRLEN];
	//u32 source_ip;        // Source IP address
	//u32 destination_ip;   // Destination IP address
	u8 protocol;
};

// This is the struct that gets loaded and interacts with the kernel
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} xdp_tcppackets_map SEC(".maps");

// Force emitting struct event into the ELF.
const struct packet_info *unused __attribute__((unused));
//const struct ipv6hdr *unused __attritribute__((unused)); 

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	//__u32 src_ip;
	//__u32 dest_ip;
	//__u16 tot_len;
	//__u16 sport;
	//__u16 dport;

	// Declare struct pinfo of type packet_info
	struct packet_info *pinfo;

	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	u64 nh_off;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}
	nh_off = sizeof(*eth);
/*	 if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ipv6;
		// ipv6 =  (struct ipv6hdr *)(((void *)eth) + ETH_HLEN);
		struct in6_addr *src;
		ipv6 = data + nh_off;
               	//if ((void *)(ipv6 + 1) > data_end) {
		if ((struct ipv6hdr)(ipv6 + 1) > data_end){	
			return XDP_PASS;
                }
                //data += ETH_HLEN + (ip->ihl * 4);
                // code
                pinfo = bpf_ringbuf_reserve(&xdp_tcppackets_map, sizeof(struct packet_info), 0);
                if (!pinfo) {
                        return XDP_PASS;
                }
		//char src_addr[INET6_ADDRSTRLEN];
		src	= (struct in6_addr *) ipv6->saddr;
		inet_ntop(AF_INET6, &src, pinfo->source_ip, INET6_ADDRSTRLEN);
                pinfo->protocol         = ipv6->nexthdr;
                bpf_ringbuf_submit(pinfo, 0);
                return XDP_PASS;
	}*/
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
                struct iphdr *ip = (struct iphdr *)(((void *)eth) + ETH_HLEN);
		struct in_addr *src;
		src->s_addr = ip->saddr;
                if (((void *)(ip + 1)) > data_end) {
                        return XDP_PASS;
                }

                // data = (void *)ip + ip->ihl;
                data += ETH_HLEN + (ip->ihl * 4);
                // code
                pinfo = bpf_ringbuf_reserve(&xdp_tcppackets_map, sizeof(struct packet_info), 0);
                if (!pinfo) {
                        return XDP_PASS;
                }
                pinfo->source_ip        = ip->saddr;
               	// pinfo->destination_ip   = ip->daddr;
                pinfo->protocol         = ip->protocol;
                bpf_ringbuf_submit(pinfo, 0);
                return XDP_PASS;
        }
	else {
		return XDP_PASS;
	}
}
