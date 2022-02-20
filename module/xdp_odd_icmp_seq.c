/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <stdlib.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)           \
    ({              \
      char ____fmt[] = fmt;       \
      bpf_trace_printk(____fmt, sizeof(____fmt),  \
             ##__VA_ARGS__);      \
    })
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"


SEC("xdp_icmp_filter")
int icmp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

    int eth_type, ip_type, icmp_type;
    int action = XDP_PASS;
	struct ethhdr *eth;
	struct iphdr *iphdr = NULL;
	struct icmphdr *icmphdr = NULL;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
        action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type < 0) {
			action = XDP_ABORTED;
			goto out;
		}
	} else goto out;

	if (ip_type == IPPROTO_ICMP) {
		icmp_type = parse_icmphdr(&nh, data_end, &icmphdr);
		if (icmp_type < 0) {
			action = XDP_ABORTED;
			goto out;
		}
	} else goto out;

	if (icmp_type == ICMP_ECHO) {
        if (bpf_ntohs(icmphdr->un.echo.sequence)%2 == 1)
            action = XDP_DROP;
    }

out:
    return action;

}

char _license[] SEC("license") = "GPL";
