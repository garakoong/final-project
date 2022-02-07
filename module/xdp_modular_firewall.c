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
#include "../common/classifier_structs.h"
#include "../common/classifier_maps.h"
#include "module_lookup_helpers.c"


SEC("xdp_modular_firewall")
int fw_classifier(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };

    int eth_type, ip_type, icmp_type;
    int action = XDP_PASS;
	__u32 module_num = MAIN_MODULE;
	struct ethhdr *eth;
	struct iphdr *iphdr = NULL;
	struct ipv6hdr *ipv6hdr = NULL;
	struct udphdr *udphdr = NULL;
	struct tcphdr *tcphdr = NULL;
	struct icmphdr_common *icmphdr = NULL;
	struct class_vector lookup_res;

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

	__builtin_memset(&lookup_res, 0xff, sizeof(struct class_vector));
	
	src_ip_lookup(iphdr, ipv6hdr, &lookup_res);
	bpf_printk("src [%lx]\n", lookup_res.word[0]);

	dst_ip_lookup(iphdr, ipv6hdr, &lookup_res);
	bpf_printk("dst [%lx]\n", lookup_res.word[0]);

	if (ip_type == IPPROTO_TCP || ip_type == IPPROTO_UDP) {
		src_port_lookup(tcphdr, udphdr, &lookup_res);
		bpf_printk("sport [%lx]\n", lookup_res.word[0]);

		dst_port_lookup(tcphdr, udphdr, &lookup_res);
		bpf_printk("dport [%lx]\n", lookup_res.word[0]);
	} else if (ip_type == IPPROTO_ICMP || ip_type == IPPROTO_ICMPV6) {
		icmp_type_lookup(icmp_type, eth_type, &lookup_res);
		bpf_printk("icmp [%lx]\n", lookup_res.word[0]);
	}

	device_lookup(ctx, &lookup_res);
	bpf_printk("dev [%lx]\n", lookup_res.word[0]);

	int w = 0;
	#pragma clang loop unroll(full)
	for (w=0; w<MAX_CLASS_WORD; w++) {
		__u64 word = lookup_res.word[w];
		
		if (word) {
			module_num = (w * 64) + get_zeroprefix(word);
			goto call_module;
		}

	}


call_module:
	bpf_printk("call_module: %d (%lx)\n", module_num, lookup_res.word[0]);
	bpf_tail_call(ctx, &firewall_modules, module_num);

out:
    return action;

}

char _license[] SEC("license") = "GPL";
