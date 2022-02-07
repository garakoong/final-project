
#ifndef __CLASSIFIER_MAPS_H
#define __CLASSIFIER_MAPS_H

#include "classifier_structs.h"

struct bpf_map_def SEC("maps") firewall_modules = {
    .type           = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(__u32),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") modules_index = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(char) * MAX_MODULE_NAME,
    .value_size     = sizeof(__u32),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") modules_info = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(struct module_info),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") firewall_info = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(__u32),
    .max_entries    = 1,
};

struct bpf_map_def SEC("maps") src_ipv4_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") dst_ipv4_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") src_ipv6_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(struct in6_addr),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") dst_ipv6_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(struct in6_addr),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") src_ipv4_lpm_vector = {
    .type           = BPF_MAP_TYPE_LPM_TRIE,
    .key_size       = ipv4_lpm_key_size,
    .value_size     = sizeof(struct class_lpm_value),
    .max_entries    = MAX_MODULE_ENTRIES,
    .map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") dst_ipv4_lpm_vector = {
    .type           = BPF_MAP_TYPE_LPM_TRIE,
    .key_size       = ipv4_lpm_key_size,
    .value_size     = sizeof(struct class_lpm_value),
    .max_entries    = MAX_MODULE_ENTRIES,
    .map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") src_ipv6_lpm_vector = {
    .type           = BPF_MAP_TYPE_LPM_TRIE,
    .key_size       = ipv6_lpm_key_size,
    .value_size     = sizeof(struct class_lpm_value),
    .max_entries    = MAX_MODULE_ENTRIES,
    .map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") dst_ipv6_lpm_vector = {
    .type           = BPF_MAP_TYPE_LPM_TRIE,
    .key_size       = ipv6_lpm_key_size,
    .value_size     = sizeof(struct class_lpm_value),
    .max_entries    = MAX_MODULE_ENTRIES,
    .map_flags      = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") tcp_sport_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u16),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") tcp_dport_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u16),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") udp_sport_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u16),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") udp_dport_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u16),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") icmp_type_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u8),
	.value_size     = sizeof(struct class_vector),
	.max_entries    = 256,
};

struct bpf_map_def SEC("maps") icmpv6_type_vector = {
	.type           = BPF_MAP_TYPE_HASH,
	.key_size       = sizeof(__u8),
	.value_size     = sizeof(struct class_vector),
	.max_entries    = 256,
};

struct bpf_map_def SEC("maps") dev_vector = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(struct class_vector),
    .max_entries    = MAX_MODULE_ENTRIES,
};

struct bpf_map_def SEC("maps") module_stats = {
    .type           = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(struct stats_rec),
    .max_entries    = MAX_MODULE_ENTRIES,
};

#endif