// +build ignore

//#include "stdio.h"
#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

// This is the struct that contains packet info about the packet.
// Can be further expanded to get more details about the packet.

struct packet_info {
	u32 source_ip;        // Source IP address
	u32 destination_ip;   // Destination IP address
	u16 total_length;     // Total length of packet in bytes
	u16 source_port;      // Source Port
	u16 destination_port; // Destination Port;
	u8 protocol;
};

// This is the struct that gets loaded and interacts with the kernel
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} xdp_tcppackets_map SEC(".maps");

// Force emitting struct event into the ELF.
const struct packet_info *unused __attribute__((unused));

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	// Declare struct pinfo of type packet_info
	struct packet_info *pinfo;

	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;	
	struct ethhdr *eth = data;
	
	u64 nh_off = sizeof(*eth);

	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}
	
	//struct iphdr *ip = (struct iphdr *)(((void *)eth) + ETH_HLEN);
	struct iphdr *ip = data  + nh_off;
	if (((void *)(ip + 1)) > data_end) {
		return XDP_PASS;
	}

	data += ETH_HLEN + (ip->ihl * 4);
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = data;
		if (data + sizeof(*tcp) > data_end) {
			return XDP_PASS;
		}
		if ((tcp->syn == 1) && (tcp->ack == 0)) {
			pinfo = bpf_ringbuf_reserve(&xdp_tcppackets_map, sizeof(struct packet_info), 0);
			if (!pinfo) {
				return XDP_PASS;
			}
			pinfo->source_ip        = ip->saddr;
			pinfo->destination_ip   = ip->daddr;
			pinfo->total_length     = __bpf_ntohs(ip->tot_len);
			pinfo->source_port      = __bpf_ntohs(tcp->source);
			pinfo->destination_port = __bpf_ntohs(tcp->dest);
			pinfo->protocol         = ip->protocol;
			bpf_ringbuf_submit(pinfo, 0);
			return XDP_PASS;
		} else {
			return XDP_PASS;
		}
	} 
	if (ip->protocol == IPPROTO_UDP) {
		// UDP code
		struct udphdr *udp = data;
		if (data + sizeof(*udp) > data_end) {
			return XDP_PASS;
		}
		pinfo = bpf_ringbuf_reserve(&xdp_tcppackets_map, sizeof(struct packet_info), 0);
		if (!pinfo) {
			return XDP_PASS;
		}
		pinfo->source_ip        = ip->saddr;
		pinfo->destination_ip   = ip->daddr;
		pinfo->total_length     = __bpf_ntohs(ip->tot_len);
		pinfo->source_port      = __bpf_ntohs(udp->source);
		pinfo->destination_port = __bpf_ntohs(udp->dest);
		pinfo->protocol         = ip->protocol;
		bpf_ringbuf_submit(pinfo, 0);
		return XDP_PASS;
	} 
	if (ip->protocol == IPPROTO_ICMP) {
		// ICMP code
		struct icmphdr *icmp = data;
		if (data + sizeof(*icmp) > data_end) {
			return XDP_PASS;
		}
		pinfo = bpf_ringbuf_reserve(&xdp_tcppackets_map, sizeof(struct packet_info), 0);
		if (!pinfo) {
			return XDP_PASS;
		}
		pinfo->source_ip        = ip->saddr;
		pinfo->destination_ip   = ip->daddr;
		pinfo->total_length     = __bpf_ntohs(ip->tot_len);
		pinfo->source_port      = __bpf_ntohs(icmp->code);
		pinfo->destination_port = __bpf_ntohs(icmp->un.echo.sequence);
		pinfo->protocol         = ip->protocol;
		bpf_ringbuf_submit(pinfo, 0);
		return XDP_PASS;
	}
	return XDP_PASS;
}
