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
#include "../common/firewall_common.h"
#include "../common/module_structs.h"
#include "../common/module_maps.h"
#include "rule_lookup_helpers.h"

SEC("xdp_firewall_module")
int fw_module(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

    int eth_type, ip_type, icmp_type;
    int action = XDP_PASS;
	__u32 rule_num = POLICY_RULE;
	struct ethhdr *eth;
	struct iphdr *iphdr = NULL;
	struct ipv6hdr *ipv6hdr = NULL;
	struct udphdr *udphdr = NULL;
	struct tcphdr *tcphdr = NULL;
	struct icmphdr_common *icmphdr = NULL;
	struct rule_vector lookup_res;
	struct rule_info *info;

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
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type < 0) {
			action = XDP_ABORTED;
			goto out;
		}
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
	} else if (ip_type == IPPROTO_ICMP || ip_type == IPPROTO_ICMPV6) {
		icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
		if (icmp_type < 0) {
			action = XDP_ABORTED;
			goto out;
		}
	} else goto out;


	__builtin_memset(&lookup_res, 0xff, sizeof(struct rule_vector));

    src_ip_lookup(iphdr, ipv6hdr, &lookup_res);
	bpf_printk("saddr (%lx)\n", lookup_res.word[0]);

	dst_ip_lookup(iphdr, ipv6hdr, &lookup_res);
	bpf_printk("daddr (%lx)\n", lookup_res.word[0]);

	if (ip_type == IPPROTO_TCP || ip_type == IPPROTO_UDP) {
		src_port_lookup(tcphdr, udphdr, &lookup_res);
		bpf_printk("sport (%lx)\n", lookup_res.word[0]);

		dst_port_lookup(tcphdr, udphdr, &lookup_res);
		bpf_printk("dport (%lx)\n", lookup_res.word[0]);
	} else if (ip_type == IPPROTO_ICMP || ip_type == IPPROTO_ICMPV6) {
		icmp_type_lookup(icmp_type, eth_type, &lookup_res);
		bpf_printk("icmp (%lx)\n", lookup_res.word[0]);
	}

	device_lookup(ctx, &lookup_res);
	bpf_printk("dev (%lx)\n", lookup_res.word[0]);

	int w = 0;
	#pragma clang loop unroll(full)
	for (w=0; w<MAX_RULE_WORD; w++) {
		__u64 word = lookup_res.word[w];
		if (word) {
			rule_num = (w * 64) + get_zeroprefix(word);
			goto verdict;
		}
	}
	
verdict:
	info = bpf_map_lookup_elem(&rules_info, &rule_num);
	if (info) {
		int rule_action = info->action;
		bpf_printk("action(%d): %d (%lx)\n", rule_num, rule_action, lookup_res.word[0]);
		return rule_action;
	}

out:
	bpf_printk("action: %d\n", action);
    return action;
}

char _license[] SEC("license") = "GPL";
