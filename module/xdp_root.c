/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"
#include "../common/firewall_common.h"
#include "../common/root_maps.h"

SEC("xdp_firewall_root")
int fw_root(struct xdp_md *ctx)
{
    bpf_tail_call(ctx, &firewall_program, 0);
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
