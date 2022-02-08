#ifndef __COMMON_MANAGEMENT_HELPERS_H
#define __COMMON_MANAGEMENT_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "../common/classifier_structs.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

__u16 swapportendian(__u16 num) {
    return (num>>8) | (num<<8);
}

void print_rulekey(struct rule_key *rule_key) {
	//source
	if (rule_key->AF == AF_INET) {
		char ipv4_addr[16];
		if (rule_key->src_ipv4 != 0) {
			if (inet_ntop(AF_INET, &rule_key->src_ipv4, ipv4_addr, sizeof(ipv4_addr)) != NULL) {
				printf("%s\t", ipv4_addr);
			}
		} else {
			__u32 prefix = rule_key->src_ipv4_lpm.word[0];
			if (inet_ntop(AF_INET, &rule_key->src_ipv4_lpm.word[1], ipv4_addr, sizeof(ipv4_addr)) != NULL) {
				printf("%s/%d\t", ipv4_addr, prefix);
			}
		}
	} else if (rule_key->AF == AF_INET6) {
		char ipv6_addr[40];
		if (rule_key->src_ipv6.s6_addr32[0] != 0 || rule_key->src_ipv6.s6_addr32[1] != 0 ||
			rule_key->src_ipv6.s6_addr32[2] != 0 || rule_key->src_ipv6.s6_addr32[3] != 0) {
			if (inet_ntop(AF_INET6, &rule_key->src_ipv6, ipv6_addr, sizeof(ipv6_addr)) != NULL) {
				printf("%s\t", ipv6_addr);
			}
		} else {
			struct in6_addr ipv6;
			__u32 prefix = rule_key->src_ipv6_lpm.word[0];
			ipv6.s6_addr32[0] = rule_key->src_ipv6_lpm.word[1];
			ipv6.s6_addr32[1] = rule_key->src_ipv6_lpm.word[2];
			ipv6.s6_addr32[2] = rule_key->src_ipv6_lpm.word[3];
			ipv6.s6_addr32[3] = rule_key->src_ipv6_lpm.word[4];
			if (inet_ntop(AF_INET6, &ipv6, ipv6_addr, sizeof(ipv6_addr)) != NULL) {
				printf("%s/%d\t", ipv6_addr, prefix);
			}
		}
	} else printf("*\t\t");

	//dest
	if (rule_key->AF == AF_INET) {
		char ipv4_addr[16];
		if (rule_key->dst_ipv4 != 0) {
			if (inet_ntop(AF_INET, &rule_key->dst_ipv4, ipv4_addr, sizeof(ipv4_addr)) != NULL) {
				printf("%s\t", ipv4_addr);
			}
		} else {
			__u32 prefix = rule_key->dst_ipv4_lpm.word[0];
			if (inet_ntop(AF_INET, &rule_key->dst_ipv4_lpm.word[1], ipv4_addr, sizeof(ipv4_addr)) != NULL) {
				printf("%s/%d\t", ipv4_addr, prefix);
			}
		}
	} else if (rule_key->AF == AF_INET6) {
		char ipv6_addr[40];
		if (rule_key->dst_ipv6.s6_addr32[0] != 0 || rule_key->dst_ipv6.s6_addr32[1] != 0 ||
			rule_key->dst_ipv6.s6_addr32[2] != 0 || rule_key->dst_ipv6.s6_addr32[3] != 0) {
			if (inet_ntop(AF_INET6, &rule_key->dst_ipv6, ipv6_addr, sizeof(ipv6_addr)) != NULL) {
				printf("%s\t", ipv6_addr);
			}
		} else {
			struct in6_addr ipv6;
			__u32 prefix = rule_key->dst_ipv6_lpm.word[0];
			ipv6.s6_addr32[0] = rule_key->dst_ipv6_lpm.word[1];
			ipv6.s6_addr32[1] = rule_key->dst_ipv6_lpm.word[2];
			ipv6.s6_addr32[2] = rule_key->dst_ipv6_lpm.word[3];
			ipv6.s6_addr32[3] = rule_key->dst_ipv6_lpm.word[4];
			if (inet_ntop(AF_INET6, &ipv6, ipv6_addr, sizeof(ipv6_addr)) != NULL) {
				printf("%s/%d\t", ipv6_addr, prefix);
			}
		}
	} else printf("*\t\t");

	//prot
	if (rule_key->proto == IPPROTO_TCP) {
		printf("tcp\t");
	} else if (rule_key->proto == IPPROTO_UDP) {
		printf("udp\t");
	} else if (rule_key->proto == IPPROTO_ICMP) {
		printf("icmp\t");
	} else if (rule_key->proto == IPPROTO_ICMPV6) {
		printf("icmpv6\t");
	} else printf("*\t");

	//dev
	if (rule_key->ifindex != 0) {
		char ifname[IF_NAMESIZE];
		if (if_indextoname(rule_key->ifindex, ifname) != NULL) {
			printf("%s\t", ifname);
		}
	} else printf("*\t");

	int count_etc = 0;

	if (rule_key->proto == IPPROTO_TCP || rule_key->proto == IPPROTO_UDP) {
		//sport
		if (rule_key->sport != 0) {
			if (count_etc > 0)
				printf(", ");
			__u16 sport = swapportendian(rule_key->sport);
			printf("spt: %hu", sport);
			count_etc++;
		}
		//dport
		if (rule_key->dport != 0) {
			if (count_etc > 0)
				printf(", ");
			__u16 dport = swapportendian(rule_key->dport);
			printf("dpt: %hu", dport);
			count_etc++;
		}
	}

	if (rule_key->proto == IPPROTO_ICMP || rule_key->proto == IPPROTO_ICMPV6) {
		//icmp type
		if (rule_key->icmp_type == ICMP_ECHO || rule_key->icmp_type == ICMPV6_ECHO_REQUEST) {
			if (count_etc > 0)
				printf(", ");
			printf("echo-request");
			count_etc++;
		} else if (rule_key->icmp_type == ICMP_ECHOREPLY || rule_key->icmp_type == ICMPV6_ECHO_REPLY) {
			if (count_etc > 0)
				printf(", ");
			printf("echo-reply");
			count_etc++;
		}
	}

	printf("\t\t");
}

void print_stats(int map_fd, __u32 index)
{
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct stats_rec recs[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if (bpf_map_lookup_elem(map_fd, &index, recs)) {
		fprintf(stderr, "ERR: Reading stats record.\n");
		return;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += recs[i].match_packets;
		sum_bytes += recs[i].match_bytes;
	}
	
	printf("%16llu%16llu", sum_pkts, sum_bytes);
}

#endif