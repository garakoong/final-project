#ifndef __COMMON_FIREWALL_H
#define __COMMON_FIREWALL_H
#define MAX_MODULE 500
#define MAIN_MODULE 500
#define MAX_CLASS_WORD 8
#define MAX_MODULE_NAME 64
#define MAX_RULE 3000
#define MAX_RULE_WORD 50
#define POLICY_RULE 3000
#define MAX_RULE_ENTRIES (MAX_RULE_WORD * 64)
#define MAX_MODULE_ENTRIES (MAX_CLASS_WORD * 64)

#include <linux/bpf.h>
#include <linux/in6.h>

struct class_vector {
    __u64 word[MAX_CLASS_WORD];
};

struct class_lpm_value {
    __u32 prefixlen;
    struct class_vector vector;
};

struct rule_vector {
    __u64 word[MAX_RULE_WORD];
};

struct rule_lpm_value {
    __u32 prefixlen;
    struct rule_vector vector;
};

union ipv4_lpm_key {
    __u32 word[2];
    __u8 byte[8];
};

union ipv6_lpm_key {
    __u32 word[5];
    __u8 byte[20];
};

struct rule_key {
    int AF;
    __u32 src_ipv4;
    __u32 dst_ipv4;
    struct in6_addr src_ipv6;
    struct in6_addr dst_ipv6;
    union ipv4_lpm_key src_ipv4_lpm;
    union ipv4_lpm_key dst_ipv4_lpm;
    union ipv6_lpm_key src_ipv6_lpm;
    union ipv6_lpm_key dst_ipv6_lpm;
    __u8 proto;
    __u16 sport;
    __u16 dport;
    __u8 icmp_type;
    __u32 ifindex;
};

struct stats_rec {
    __u64 match_packets;
	__u64 match_bytes;
};

#define ipv6_lpm_key_size (sizeof(union ipv6_lpm_key))
#define ipv4_lpm_key_size (sizeof(union ipv4_lpm_key))

#endif