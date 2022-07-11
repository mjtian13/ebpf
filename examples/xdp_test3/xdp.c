// +build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16
#define ETH_HLEN 14
#define IPPROTO_TCP 6

/*
struct pair {
	u32 dest_ip;
	u32 tot_len;
};
*/

/* Define an LRU hash map for storing packet count by source IPv4 address */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // source IPv4 address saddr
	__type(value, __u32); // printing the struct pair
} xdp_tcppackets_map SEC(".maps");

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	__u32 src_ip_key;
	__u32 dest_ip;
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_DROP;
	}

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (struct iphdr *)(((void *)eth) + ETH_HLEN);

		if (((void *)(ip + 1)) > data_end) {
			// return XDP_PASS;
			return XDP_DROP;
		}

		if (ip->protocol == IPPROTO_TCP) {
			// code
			src_ip_key = ip->saddr;
			dest_ip    = ip->daddr;
			// info.dest_ip = ip->daddr;
			// info.tot_len = ip->tot_len;
			bpf_map_update_elem(&xdp_tcppackets_map, &src_ip_key, &dest_ip, BPF_ANY);
			return XDP_PASS;
		}

	}

	else {
		return XDP_DROP;
	}

	/*
	__u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip);
	if (!pkt_count) {
		// No entry in the map for this IP address yet, so set the initial value to 1.
		__u32 init_pkt_count = 1;
		bpf_map_update_elem(&xdp_stats_map, &ip, &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP address,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}
	*/
	return XDP_DROP;
}
