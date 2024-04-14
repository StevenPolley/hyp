/*
Copyright © 2024 Steven Polley <himself@stevenpolley.net>
*/

//go:build ignore
#include "vmlinux.h"
#include "bpf_endian.h"
#include <bpf/bpf_helpers.h>


char __license[] SEC("license") = "BSD";

#define ETH_P_IP 0x0800
#define IP_FRAGMENTED 65343

// representation of knock data that gets sent to userspace
struct knock_data {
	__u32 srcip; // 4 bytes
	__u16 dstport; // 2 bytes
	__u16 pad; // required padding - struct must be multiple of 4 bytes
};

// ring buffer used to send data to userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} rb SEC(".maps");

// force emitting struct event into the ELF
const struct knock_data *unused __attribute__((unused));

// hook into xpress data path attach point
SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	
	// xdp gives us the raw frame with no structures, it must be parsed
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// parse ethernet header
	struct ethhdr *eth = data;

	if ((void *)eth + sizeof(*eth) <= data_end) {
		// parse IP header
		struct iphdr *ip = data + sizeof(*eth);
		if ((void *)ip + sizeof(*ip) <= data_end) {
			if (ip->protocol == IPPROTO_UDP) {
				// parse UDP header
				struct udphdr *udp = (void *)ip + sizeof(*ip);
				if ((void *)udp + sizeof(*udp) <= data_end)
				{
					// pack into knock structure and send to userspace
					struct knock_data knock;
					knock.srcip = bpf_ntohl(ip->saddr);
					knock.dstport = bpf_htons(udp->dest);
					knock.pad = 0;
					bpf_ringbuf_output(&rb, &knock, sizeof(knock), BPF_RB_FORCE_WAKEUP);
				}
			}
		}
	}

	return XDP_PASS;
}
