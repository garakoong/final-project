
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
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(__u32),
    .max_entries    = 1000,
};

#endif