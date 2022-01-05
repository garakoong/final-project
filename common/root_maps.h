
#ifndef __ROOT_MAPS_H
#define __ROOT_MAPS_H

#include "firewall_common.h"

struct bpf_map_def SEC("maps") firewall_program = {
    .type           = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(__u32),
    .max_entries    = 1,
};

struct bpf_map_def SEC("maps") operating_dev = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(__u32),
    .max_entries    = 1000,
};

struct bpf_map_def SEC("maps") fw_stats = {
    .type           = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(struct stats_rec),
    .max_entries    = 1,
};

#endif