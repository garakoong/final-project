static __always_inline
void src_ip_lookup(struct iphdr *iph, struct ipv6hdr *ip6h, struct class_vector *vector) {

    __u32 w;
    struct class_vector *lookup_res = NULL;
    struct class_lpm_value *lpm_val = NULL;

    if (iph != NULL) {

        union ipv4_lpm_key lpm_key;

        __builtin_memset(&lpm_key, 0, ipv4_lpm_key_size);

        lpm_key.word[0] = 32;
        lpm_key.word[1] = iph->saddr;

        lookup_res = bpf_map_lookup_elem(&src_ipv4_vector, &iph->saddr);

        lpm_val = bpf_map_lookup_elem(&src_ipv4_lpm_vector, &lpm_key);
        if (lpm_val) {
            #pragma clang loop unroll(full)
            for (w=0; w<MAX_CLASS_WORD; w++) {
                __u64 word = lpm_val->vector.word[w];
                if (lookup_res)
                    word |= lookup_res->word[w];
                vector->word[w] &= word;
            }
        }

    } else if (ip6h != NULL) {
    

        union ipv6_lpm_key lpm_key;

        __builtin_memset(&lpm_key, 0, ipv6_lpm_key_size);

        lpm_key.word[0] = 128;
        lpm_key.word[1] = ip6h->saddr.s6_addr32[0];
        lpm_key.word[2] = ip6h->saddr.s6_addr32[1];
        lpm_key.word[3] = ip6h->saddr.s6_addr32[2];
        lpm_key.word[4] = ip6h->saddr.s6_addr32[3];

        lookup_res = bpf_map_lookup_elem(&src_ipv6_vector, &ip6h->saddr);

        lpm_val = bpf_map_lookup_elem(&src_ipv6_lpm_vector, &lpm_key);
        if (lpm_val) {
            #pragma clang loop unroll(full)
            for (w=0; w<MAX_CLASS_WORD; w++) {
                __u64 word = lpm_val->vector.word[w];
                if (lookup_res)
                    word |= lookup_res->word[w];
                vector->word[w] &= word;
            }
        }
    }

    return;
}

static __always_inline
void dst_ip_lookup(struct iphdr *iph, struct ipv6hdr *ip6h, struct class_vector *vector) {

    __u32 w = 0;
    struct class_vector *lookup_res = NULL;
    struct class_lpm_value *lpm_val = NULL;

    if (sizeof(vector->word)/sizeof(vector->word[0]) != MAX_CLASS_WORD)
        return;

    if (iph != NULL) {

        union ipv4_lpm_key lpm_key;

        __builtin_memset(&lpm_key, 0, ipv4_lpm_key_size);

        lpm_key.word[0] = 32;
        lpm_key.word[1] = iph->daddr;

        lookup_res = bpf_map_lookup_elem(&dst_ipv4_vector, &iph->daddr);

        lpm_val = bpf_map_lookup_elem(&dst_ipv4_lpm_vector, &lpm_key);
        if (lpm_val) {
            #pragma clang loop unroll(full)
            for (w=0; w<MAX_CLASS_WORD; w++) {
                __u64 word = lpm_val->vector.word[w];
                if (lookup_res)
                    word |= lookup_res->word[w];
                vector->word[w] &= word;
            }
        }

    } else if (ip6h != NULL) {


        union ipv6_lpm_key lpm_key;

        __builtin_memset(&lpm_key, 0, ipv6_lpm_key_size);

        lpm_key.word[0] = 0;
        lpm_key.word[1] = ip6h->daddr.s6_addr32[0];
        lpm_key.word[2] = ip6h->daddr.s6_addr32[1];
        lpm_key.word[3] = ip6h->daddr.s6_addr32[2];
        lpm_key.word[4] = ip6h->daddr.s6_addr32[3];

        lookup_res = bpf_map_lookup_elem(&dst_ipv6_vector, &ip6h->daddr);

        lpm_val = bpf_map_lookup_elem(&dst_ipv6_lpm_vector, &lpm_key);
        if (lpm_val) {
            #pragma clang loop unroll(full)
            for (w=0; w<MAX_CLASS_WORD; w++) {
                __u64 word = lpm_val->vector.word[w];
                if (lookup_res)
                    word |= lookup_res->word[w];
                vector->word[w] &= word;
            }
        }

    }

    return;
}

static __always_inline
void src_port_lookup(struct tcphdr *tcph, struct udphdr *udph, struct class_vector *vector) {

    struct class_vector *wildcard_res = NULL;
    struct class_vector *lookup_res;
    __u16 *key = 0;
    __u32 w = 0;

    if (tcph != NULL) {
        wildcard_res = bpf_map_lookup_elem(&tcp_sport_vector, &key);

        lookup_res = bpf_map_lookup_elem(&tcp_sport_vector, &tcph->source);

        if (wildcard_res) {
            #pragma clang loop unroll(full)
           for(w=0; w<MAX_CLASS_WORD; w++) {
                __u64 word = wildcard_res->word[w];
                if (lookup_res) {
                    word |= lookup_res->word[w];
                }
                vector->word[w] &= word;
            }
        }
    } else if (udph != NULL) {
        wildcard_res = bpf_map_lookup_elem(&udp_sport_vector, &key);

        lookup_res = bpf_map_lookup_elem(&udp_sport_vector, &udph->source);

        if (wildcard_res) {
            #pragma clang loop unroll(full)
            for(w=0; w<MAX_CLASS_WORD; w++) {
                __u64 word = wildcard_res->word[w];
                if (lookup_res) {
                    word |= lookup_res->word[w];
                }
                vector->word[w] &= word;
            }
        }
    }

    return;
}

static __always_inline
void dst_port_lookup(struct tcphdr *tcph, struct udphdr *udph, struct class_vector *vector) {

    struct class_vector *wildcard_res = NULL;
    struct class_vector *lookup_res;
    __u16 *key = 0;
    __u32 w = 0;

    if (tcph != NULL) {
        wildcard_res = bpf_map_lookup_elem(&tcp_dport_vector, &key);

        lookup_res = bpf_map_lookup_elem(&tcp_dport_vector, &tcph->dest);

        if (wildcard_res) {
            #pragma clang loop unroll(full)
            for(w=0; w<MAX_CLASS_WORD; w++) {
                __u64 word = wildcard_res->word[w];
                if (lookup_res) {
                    word |= lookup_res->word[w];
                }
                vector->word[w] &= word;
            }
        }
    } else if (udph != NULL) {
        wildcard_res = bpf_map_lookup_elem(&udp_dport_vector, &key);

        lookup_res = bpf_map_lookup_elem(&udp_dport_vector, &udph->dest);

        if (wildcard_res) {
            #pragma clang loop unroll(full)
            for(w=0; w<MAX_CLASS_WORD; w++) {
                __u64 word = wildcard_res->word[w];
                if (lookup_res) {
                    word |= lookup_res->word[w];
                }
                vector->word[w] &= word;
            }
        }
    }

    return;
}

static __always_inline
void device_lookup(struct xdp_md *ctx, struct class_vector *vector) {

    struct class_vector *wildcard_res = NULL;
    struct class_vector *lookup_res;
    __u32 key = 0;
    int w;

    wildcard_res = bpf_map_lookup_elem(&dev_vector, &key);

    key = ctx->ingress_ifindex;
    lookup_res = bpf_map_lookup_elem(&dev_vector, &key);

    if (wildcard_res) {
        #pragma clang loop unroll(full)
        for(w=0; w<MAX_CLASS_WORD; w++) {
            __u64 word = wildcard_res->word[w];
            if (lookup_res) {
                word |= lookup_res->word[w];
            }
            vector->word[w] &= word;
        }
    }

    return;
}

static __always_inline
__u32 get_zeroprefix(__u64 x) {
    __u64 y;
    __u32 n = 64;

    y = x >> 32;
    if (y != 0) {
        n = n - 32;
        x = y;
    }

    y = x >> 16;
    if (y != 0) {
        n = n - 16;
        x = y;
    }

    y = x >> 8;
    if (y != 0) {
        n = n - 8;
        x = y;
    }

    y = x >> 4;
    if (y != 0) {
        n = n - 4;
        x = y;
    }

    y = x >> 2;
    if (y != 0) {
        n = n - 2;
        x = y;
    }

    y = x >> 1;
    if (y != 0) {
        return n - 2;
    }

    return n - x;
}