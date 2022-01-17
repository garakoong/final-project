#ifndef __MODULE_MAPS_H
#define __MODULE_MAPS_H

#include <linux/bpf.h>
#include "module_maps.h"

struct bpf_map_def SEC("maps") rules_info = {
	.type           = BPF_MAP_TYPE_ARRAY,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(struct rule_info),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") src_ipv4_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") dst_ipv4_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") src_ipv6_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct in6_addr),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") dst_ipv6_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(struct in6_addr),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") src_ipv4_lpm_vector = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = ipv4_lpm_key_size,
	.value_size     = sizeof(struct rule_lpm_value),
	.max_entries    = MAX_RULE_ENTRIES,
	.map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") dst_ipv4_lpm_vector = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = ipv4_lpm_key_size,
	.value_size     = sizeof(struct rule_lpm_value),
	.max_entries    = MAX_RULE_ENTRIES,
	.map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") src_ipv6_lpm_vector = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = ipv6_lpm_key_size,
	.value_size     = sizeof(struct rule_lpm_value),
	.max_entries    = MAX_RULE_ENTRIES,
	.map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") dst_ipv6_lpm_vector = {
	.type           = BPF_MAP_TYPE_LPM_TRIE,
	.key_size       = ipv6_lpm_key_size,
	.value_size     = sizeof(struct rule_lpm_value),
	.max_entries    = MAX_RULE_ENTRIES,
	.map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") tcp_sport_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u16),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") tcp_dport_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u16),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") udp_sport_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u16),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") udp_dport_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u16),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") dev_vector = {
	.type           = BPF_MAP_TYPE_ARRAY,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(struct rule_vector),
	.max_entries    = MAX_RULE_ENTRIES,
};

struct bpf_map_def SEC("maps") rule_stats = {
	.type           = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(struct stats_rec),
	.max_entries    = MAX_RULE_ENTRIES,
};


#endif