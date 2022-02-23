#ifndef __RULE_MANAGEMENT_HELPERS_H
#define __RULE_MANAGEMENT_HELPERS_H

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
#include "../common/module_structs.h"
#include "loader_helpers.h"
#include "common_mgmt_helpers.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

void shift_right_vector(int index, struct rule_vector *vector) {

	__u64 val = 0;
	int target_word = index / 64;
	int target_bit = 63 - (index % 64);
	int i;

	for (i=target_word; i<MAX_RULE_WORD; i++) {
		if (i == target_word) {
			__u64 mask = 0;
			if (target_bit < 63) {
				mask = ((__u64)1 << target_bit) - 1;
			} else {
				mask = (((__u64)1 << 63) - 1) | ((__u64)1 << 63);
			}
			__u64 left_word = vector->word[i] & ~mask;
			__u64 right_word = (vector->word[i] >> 1) & mask;
			val = vector->word[i] % 2;
			vector->word[i] = (left_word | right_word);
		} else {
			__u64 new_word = (vector->word[i] >> 1) | (val << 63);
			val = vector->word[i] % 2;
			vector->word[i] = new_word;
		}
	}

	return;
}

void shift_left_vector(int index, struct rule_vector *vector) {

	__u64 val = 0;
	int target_word = index / 64;
	int target_bit = 63 - (index % 64);
	int i;

	for (i=MAX_RULE_WORD-1; i>=target_word; i--) {
		if (i == target_word) {
			__u64 mask = 0;
			if (target_bit < 63) {
				mask = ((__u64)1 << target_bit) - 1;
			} else {
				mask = (((__u64)1 << 63) - 1) | ((__u64)1 << 63);
			}
			__u64 left_word = vector->word[i] & ~mask & ~((__u64)1 << target_bit);
			__u64 right_word = (vector->word[i] << 1) & mask;
			vector->word[i] = (left_word | (right_word | val));
		} else {
			__u64 new_word = (vector->word[i] << 1) | val;
			val = vector->word[i] >> 63;
			vector->word[i] = new_word;
		}
	}

	return;
}

int set_src_ip_vector(struct config *cfg, int value) {
	
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct rule_vector vector;
	struct rule_lpm_value lpm_val;

	switch (cfg->rule_key.AF) {
		case 0:
		case AF_INET: {
			if (cfg->rule_key.src_ipv4 != 0x00000000) {
				len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv4_vector", pin_basedir, cfg->module_name);
				if (len < 0) {
					fprintf(stderr, "ERR: creating src_ipv4_vector map path.\n");
					return EXIT_FAIL_OPTION;
				}

				map_fd = bpf_obj_get(map_path);
				if (map_fd < 0) {
					fprintf(stderr, "ERR: Opening src_ipv4_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.src_ipv4, &vector) == -1) {
					memset(&vector, 0, sizeof(vector));
				}
				int target_word = cfg->rule_num / 64;
				int target_bit = 63 - (cfg->rule_num % 64);
				if (value)
					vector.word[target_word] |= (__u64)1 << target_bit;
				else
					vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.src_ipv4, &vector, 0)) {
					fprintf(stderr, "ERR: Updating src_ipv4_vector map.\n");
					return EXIT_FAIL_BPF;
				}
			} else {
				len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv4_lpm_vector", pin_basedir, cfg->module_name);
				if (len < 0) {
					fprintf(stderr, "ERR: creating src_ipv4_lpm_vector map path.\n");
					return EXIT_FAIL_OPTION;
				}

				map_fd = bpf_obj_get(map_path);
				if (map_fd < 0) {
					fprintf(stderr, "ERR: Opening src_ipv4_lpm_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.src_ipv4_lpm, &lpm_val) == -1) {
					memset(&lpm_val, 0, sizeof(lpm_val));
				}
				lpm_val.prefixlen = cfg->rule_key.src_ipv4_lpm.word[0];
				int target_word = cfg->rule_num / 64;
				int target_bit = 63 - (cfg->rule_num % 64);
				if (value)
					lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
				else
					lpm_val.vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.src_ipv4_lpm, &lpm_val, 0)) {
					fprintf(stderr, "ERR: Updating src_ipv4_lpm_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				union ipv4_lpm_key key;
				key.word[0] = 31;
				key.word[1] = cfg->rule_key.src_ipv4_lpm.word[1];

				while (bpf_map_lookup_elem(map_fd, &key, &lpm_val) != -1) {

					key.word[0] = lpm_val.prefixlen;

					if (key.word[0] <= cfg->rule_key.src_ipv4_lpm.word[0])
						break;

					if (value)
						lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
					else
						lpm_val.vector.word[target_word] &= ~((__u64)1 << target_bit);
					if (bpf_map_update_elem(map_fd, &key, &lpm_val, 0)) {
						fprintf(stderr, "ERR: Updating src_ipv4_lpm_vector map.\n");
						return EXIT_FAIL_BPF;
					}

					key.word[0] = lpm_val.prefixlen - 1;
				}

			}
			if (cfg->rule_key.AF == AF_INET)
				break;
		}
		case AF_INET6: {
			if (cfg->rule_key.src_ipv6.s6_addr32[0] != 0x00000000 || cfg->rule_key.src_ipv6.s6_addr32[1] != 0x00000000 ||
				cfg->rule_key.src_ipv6.s6_addr32[2] != 0x00000000 || cfg->rule_key.src_ipv6.s6_addr32[3] != 0x00000000) {
				len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv6_vector", pin_basedir, cfg->module_name);
				if (len < 0) {
					fprintf(stderr, "ERR: creating src_ipv6_vector map path.\n");
					return EXIT_FAIL_OPTION;
				}

				map_fd = bpf_obj_get(map_path);
				if (map_fd < 0) {
					fprintf(stderr, "ERR: Opening src_ipv6_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.src_ipv6, &vector) == -1) {
					memset(&vector, 0, sizeof(vector));
				}
				int target_word = cfg->rule_num / 64;
				int target_bit = 63 - (cfg->rule_num % 64);
				if (value)
					vector.word[target_word] |= (__u64)1 << target_bit;
				else
					vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.src_ipv6, &vector, 0)) {
					fprintf(stderr, "ERR: Updating src_ipv6_vector map.\n");
					return EXIT_FAIL_BPF;
				}
			} else {
				len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv6_lpm_vector", pin_basedir, cfg->module_name);
				if (len < 0) {
					fprintf(stderr, "ERR: creating src_ipv6_lpm_vector map path.\n");
					return EXIT_FAIL_OPTION;
				}

				map_fd = bpf_obj_get(map_path);
				if (map_fd < 0) {
					fprintf(stderr, "ERR: Opening src_ipv6_lpm_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.src_ipv6_lpm, &lpm_val) == -1) {
					memset(&lpm_val, 0, sizeof(lpm_val));
				}
				lpm_val.prefixlen = cfg->rule_key.src_ipv6_lpm.word[0];
				int target_word = cfg->rule_num / 64;
				int target_bit = 63 - (cfg->rule_num % 64);
				if (value)
					lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
				else
					lpm_val.vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.src_ipv6_lpm, &lpm_val, 0)) {
					fprintf(stderr, "ERR: Updating src_ipv6_lpm_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				union ipv6_lpm_key key;
				key.word[0] = 127;
				key.word[1] = cfg->rule_key.src_ipv6_lpm.word[1];
				key.word[2] = cfg->rule_key.src_ipv6_lpm.word[2];
				key.word[3] = cfg->rule_key.src_ipv6_lpm.word[3];
				key.word[4] = cfg->rule_key.src_ipv6_lpm.word[4];

				while (bpf_map_lookup_elem(map_fd, &key, &lpm_val) != -1) {
					key.word[0] = lpm_val.prefixlen;

					if (key.word[0] <= cfg->rule_key.src_ipv4_lpm.word[0])
						break;
						
					if (value)
						lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
					else
						lpm_val.vector.word[target_word] &= ~((__u64)1 << target_bit);
					if (bpf_map_update_elem(map_fd, &key, &lpm_val, 0)) {
						fprintf(stderr, "ERR: Updating src_ipv6_lpm_vector map.\n");
						return EXIT_FAIL_BPF;
					}

					key.word[0] = lpm_val.prefixlen - 1;
				}
			}
			break;
		}
		default:
			fprintf(stderr, "ERR: Unknown address family.\n");
			return EXIT_FAIL_OPTION;
	}

	return EXIT_OK;
}

int set_dst_ip_vector(struct config *cfg, int value) {

	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct rule_vector vector;
	struct rule_lpm_value lpm_val;

	switch (cfg->rule_key.AF) {
		case 0:
		case AF_INET: {
			if (cfg->rule_key.dst_ipv4 != 0x00000000) {
				len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv4_vector", pin_basedir, cfg->module_name);
				if (len < 0) {
					fprintf(stderr, "ERR: creating dst_ipv4_vector map path.\n");
					return EXIT_FAIL_OPTION;
				}

				map_fd = bpf_obj_get(map_path);
				if (map_fd < 0) {
					fprintf(stderr, "ERR: Opening dst_ipv4_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.dst_ipv4, &vector) == -1) {
					memset(&vector, 0, sizeof(vector));
				}
				int target_word = cfg->rule_num / 64;
				int target_bit = 63 - (cfg->rule_num % 64);
				if (value)
					vector.word[target_word] |= (__u64)1 << target_bit;
				else
					vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.dst_ipv4, &vector, 0)) {
					fprintf(stderr, "ERR: Updating dst_ipv4_vector map.\n");
					return EXIT_FAIL_BPF;
				}
			} else {
				len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv4_lpm_vector", pin_basedir, cfg->module_name);
				if (len < 0) {
					fprintf(stderr, "ERR: creating dst_ipv4_lpm_vector map path.\n");
					return EXIT_FAIL_OPTION;
				}

				map_fd = bpf_obj_get(map_path);
				if (map_fd < 0) {
					fprintf(stderr, "ERR: Opening dst_ipv4_lpm_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.dst_ipv4_lpm, &lpm_val) == -1) {
					memset(&lpm_val, 0, sizeof(lpm_val));
				}
				lpm_val.prefixlen = cfg->rule_key.dst_ipv4_lpm.word[0];
				int target_word = cfg->rule_num / 64;
				int target_bit = 63 - (cfg->rule_num % 64);
				if (value)
					lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
				else
					lpm_val.vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.dst_ipv4_lpm, &lpm_val, 0)) {
					fprintf(stderr, "ERR: Updating dst_ipv4_lpm_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				union ipv4_lpm_key key;
				key.word[0] = 31;
				key.word[1] = cfg->rule_key.dst_ipv4_lpm.word[1];

				while (bpf_map_lookup_elem(map_fd, &key, &lpm_val) != -1) {
					key.word[0] = lpm_val.prefixlen;

					if (key.word[0] <= cfg->rule_key.dst_ipv4_lpm.word[0])
						break;

					if (value)
						lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
					else
						lpm_val.vector.word[target_word] &= ~((__u64)1 << target_bit);
					if (bpf_map_update_elem(map_fd, &key, &lpm_val, 0)) {
						fprintf(stderr, "ERR: Updating dst_ipv4_lpm_vector map.\n");
						return EXIT_FAIL_BPF;
					}

					key.word[0] = lpm_val.prefixlen - 1;
				}
			}
			if (cfg->rule_key.AF == AF_INET)
				break;
		}
		case AF_INET6: {
			if (cfg->rule_key.dst_ipv6.s6_addr32[0] != 0x00000000 || cfg->rule_key.dst_ipv6.s6_addr32[1] != 0x00000000 ||
				cfg->rule_key.dst_ipv6.s6_addr32[2] != 0x00000000 || cfg->rule_key.dst_ipv6.s6_addr32[3] != 0x00000000) {
				len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv6_vector", pin_basedir, cfg->module_name);
				if (len < 0) {
					fprintf(stderr, "ERR: creating dst_ipv6_vector map path.\n");
					return EXIT_FAIL_OPTION;
				}

				map_fd = bpf_obj_get(map_path);
				if (map_fd < 0) {
					fprintf(stderr, "ERR: Opening dst_ipv6_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.dst_ipv6, &vector) == -1) {
					memset(&vector, 0, sizeof(vector));
				}
				int target_word = cfg->rule_num / 64;
				int target_bit = 63 - (cfg->rule_num % 64);
				if (value)
					vector.word[target_word] |= (__u64)1 << target_bit;
				else
					vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.dst_ipv6, &vector, 0)) {
					fprintf(stderr, "ERR: Updating dst_ipv6_vector map.\n");
					return EXIT_FAIL_BPF;
				}
			} else {
				len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv6_lpm_vector", pin_basedir, cfg->module_name);
				if (len < 0) {
					fprintf(stderr, "ERR: creating dst_ipv6_lpm_vector map path.\n");
					return EXIT_FAIL_OPTION;
				}

				map_fd = bpf_obj_get(map_path);
				if (map_fd < 0) {
					fprintf(stderr, "ERR: Opening dst_ipv6_lpm_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.dst_ipv6_lpm, &lpm_val) == -1) {
					memset(&lpm_val, 0, sizeof(lpm_val));
				}
				lpm_val.prefixlen = cfg->rule_key.dst_ipv6_lpm.word[0];
				int target_word = cfg->rule_num / 64;
				int target_bit = 63 - (cfg->rule_num % 64);
				if (value)
					lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
				else
					lpm_val.vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.dst_ipv6_lpm, &lpm_val, 0)) {
					fprintf(stderr, "ERR: Updating dst_ipv6_lpm_vector map.\n");
					return EXIT_FAIL_BPF;
				}

				union ipv6_lpm_key key;
				key.word[0] = 127;
				key.word[1] = cfg->rule_key.dst_ipv6_lpm.word[1];
				key.word[2] = cfg->rule_key.dst_ipv6_lpm.word[2];
				key.word[3] = cfg->rule_key.dst_ipv6_lpm.word[3];
				key.word[4] = cfg->rule_key.dst_ipv6_lpm.word[4];

				while (bpf_map_lookup_elem(map_fd, &key, &lpm_val) != -1) {
					key.word[0] = lpm_val.prefixlen;

					if (key.word[0] <= cfg->rule_key.dst_ipv4_lpm.word[0])
						break;
						
					if (value)
						lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
					else
						lpm_val.vector.word[target_word] &= ~((__u64)1 << target_bit);
					if (bpf_map_update_elem(map_fd, &key, &lpm_val, 0)) {
						fprintf(stderr, "ERR: Updating dst_ipv6_lpm_vector map.\n");
						return EXIT_FAIL_BPF;
					}

					key.word[0] = lpm_val.prefixlen - 1;
				}
			}
			break;
		}
		default:
			fprintf(stderr, "ERR: Unknown address family.\n");
			return EXIT_FAIL_OPTION;
	}

	return EXIT_OK;
}

int set_sport_vector(struct config *cfg, int value) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct rule_vector vector;

	switch (cfg->rule_key.proto) {
		case 255:
		case IPPROTO_TCP: {
			len = snprintf(map_path, PATH_MAX, "%s/%s/tcp_sport_vector", pin_basedir, cfg->module_name);
			if (len < 0) {
				fprintf(stderr, "ERR: creating tcp_sport_vector map path.\n");
				return EXIT_FAIL_OPTION;
			}
			map_fd = bpf_obj_get(map_path);
			if (map_fd < 0) {
				fprintf(stderr, "ERR: Opening tcp_sport_vector map.\n");
				return EXIT_FAIL_BPF;
			}

			if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.sport, &vector) == -1) {
				memset(&vector, 0, sizeof(vector));
			}

			int target_word = cfg->rule_num / 64;
			int target_bit = 63 - (cfg->rule_num % 64);
			if (value)
				vector.word[target_word] |= (__u64)1 << target_bit;
			else
				vector.word[target_word] &= ~((__u64)1 << target_bit);

			if (bpf_map_update_elem(map_fd, &cfg->rule_key.sport, &vector, 0)) {
				fprintf(stderr, "ERR: Updating tcp_sport_vector map.\n");
				return EXIT_FAIL_BPF;
			}
			if (cfg->rule_key.proto == IPPROTO_TCP)
				break;
		}
		case IPPROTO_UDP: {
			len = snprintf(map_path, PATH_MAX, "%s/%s/udp_sport_vector", pin_basedir, cfg->module_name);
			if (len < 0) {
				fprintf(stderr, "ERR: creating udp_sport_vector map path.\n");
				return EXIT_FAIL_OPTION;
			}
			map_fd = bpf_obj_get(map_path);
			if (map_fd < 0) {
				fprintf(stderr, "ERR: Opening udp_sport_vector map.\n");
				return EXIT_FAIL_BPF;
			}

			if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.sport, &vector) == -1) {
				memset(&vector, 0, sizeof(vector));
			}

			int target_word = cfg->rule_num / 64;
			int target_bit = 63 - (cfg->rule_num % 64);
			if (value)
				vector.word[target_word] |= (__u64)1 << target_bit;
			else
				vector.word[target_word] &= ~((__u64)1 << target_bit);

			if (bpf_map_update_elem(map_fd, &cfg->rule_key.sport, &vector, 0)) {
				fprintf(stderr, "ERR: Updating udp_sport_vector map.\n");
				return EXIT_FAIL_BPF;
			}
			break;
		}
		default:
			fprintf(stderr, "ERR: Protocol not supported.\n");
			return EXIT_FAIL_OPTION;
	}
	return EXIT_OK;
}

int set_dport_vector(struct config *cfg, int value) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct rule_vector vector;

	switch (cfg->rule_key.proto) {
		case 255:
		case IPPROTO_TCP: {
			len = snprintf(map_path, PATH_MAX, "%s/%s/tcp_dport_vector", pin_basedir, cfg->module_name);
			if (len < 0) {
				fprintf(stderr, "ERR: creating tcp_dport_vector map path.\n");
				return EXIT_FAIL_OPTION;
			}
			map_fd = bpf_obj_get(map_path);
			if (map_fd < 0) {
				fprintf(stderr, "ERR: Opening tcp_dport_vector map.\n");
				return EXIT_FAIL_BPF;
			}

			if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.dport, &vector) == -1) {
				memset(&vector, 0, sizeof(vector));
			}

			int target_word = cfg->rule_num / 64;
			int target_bit = 63 - (cfg->rule_num % 64);
			if (value)
				vector.word[target_word] |= (__u64)1 << target_bit;
			else
				vector.word[target_word] &= ~((__u64)1 << target_bit);

			if (bpf_map_update_elem(map_fd, &cfg->rule_key.dport, &vector, 0)) {
				fprintf(stderr, "ERR: Updating tcp_dport_vector map.\n");
				return EXIT_FAIL_BPF;
			}
			if (cfg->rule_key.proto == IPPROTO_TCP)
				break;
		}
		case IPPROTO_UDP: {
			len = snprintf(map_path, PATH_MAX, "%s/%s/udp_dport_vector", pin_basedir, cfg->module_name);
			if (len < 0) {
				fprintf(stderr, "ERR: creating udp_dport_vector map path.\n");
				return EXIT_FAIL_OPTION;
			}
			map_fd = bpf_obj_get(map_path);
			if (map_fd < 0) {
				fprintf(stderr, "ERR: Opening udp_dport_vector map.\n");
				return EXIT_FAIL_BPF;
			}

			if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.dport, &vector) == -1) {
				memset(&vector, 0, sizeof(vector));
			}

			int target_word = cfg->rule_num / 64;
			int target_bit = 63 - (cfg->rule_num % 64);
			if (value)
				vector.word[target_word] |= (__u64)1 << target_bit;
			else
				vector.word[target_word] &= ~((__u64)1 << target_bit);

			if (bpf_map_update_elem(map_fd, &cfg->rule_key.dport, &vector, 0)) {
				fprintf(stderr, "ERR: Updating udp_dport_vector map.\n");
				return EXIT_FAIL_BPF;
			}
			break;
		}
		default:
			fprintf(stderr, "ERR: Protocol not supported.\n");
			return EXIT_FAIL_OPTION;
	}
	return EXIT_OK;
}

int set_icmp_type_vector(struct config *cfg, int value) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct rule_vector vector;

	switch (cfg->rule_key.proto) {
		case 255:
		case IPPROTO_ICMP: {
			len = snprintf(map_path, PATH_MAX, "%s/%s/icmp_type_vector", pin_basedir, cfg->module_name);
			if (len < 0) {
				fprintf(stderr, "ERR: creating icmp_type_vector map path.\n");
				return EXIT_FAIL_OPTION;
			}
			map_fd = bpf_obj_get(map_path);
			if (map_fd < 0) {
				fprintf(stderr, "ERR: Opening icmp_type_vector map.\n");
				return EXIT_FAIL_BPF;
			}

			if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.icmp_type, &vector) == -1) {
				memset(&vector, 0, sizeof(vector));
			}

			int target_word = cfg->rule_num / 64;
			int target_bit = 63 - (cfg->rule_num % 64);
			if (value)
				vector.word[target_word] |= (__u64)1 << target_bit;
			else
				vector.word[target_word] &= ~((__u64)1 << target_bit);

			if (bpf_map_update_elem(map_fd, &cfg->rule_key.icmp_type, &vector, 0)) {
				fprintf(stderr, "ERR: Updating icmp_type_vector map.\n");
				return EXIT_FAIL_BPF;
			}
			if (cfg->rule_key.proto == IPPROTO_ICMP)
				break;
		}
		case IPPROTO_ICMPV6: {
			len = snprintf(map_path, PATH_MAX, "%s/%s/icmpv6_type_vector", pin_basedir, cfg->module_name);
			if (len < 0) {
				fprintf(stderr, "ERR: creating icmpv6_type_vector map path.\n");
				return EXIT_FAIL_OPTION;
			}
			map_fd = bpf_obj_get(map_path);
			if (map_fd < 0) {
				fprintf(stderr, "ERR: Opening icmpv6_type_vector map.\n");
				return EXIT_FAIL_BPF;
			}

			if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.icmp_type, &vector) == -1) {
				memset(&vector, 0, sizeof(vector));
			}

			int target_word = cfg->rule_num / 64;
			int target_bit = 63 - (cfg->rule_num % 64);
			if (value)
				vector.word[target_word] |= (__u64)1 << target_bit;
			else
				vector.word[target_word] &= ~((__u64)1 << target_bit);

			if (bpf_map_update_elem(map_fd, &cfg->rule_key.icmp_type, &vector, 0)) {
				fprintf(stderr, "ERR: Updating icmpv6_type_vector map.\n");
				return EXIT_FAIL_BPF;
			}
			break;
		}
		default:
			fprintf(stderr, "ERR: Protocol not supported.\n");
			return EXIT_FAIL_OPTION;
	}
	return EXIT_OK;
}

int set_dev_vector(struct config *cfg, int value) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct rule_vector vector;;

	len = snprintf(map_path, PATH_MAX, "%s/%s/dev_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dev_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}
	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dev_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(map_fd, &cfg->rule_key.ifindex, &vector) == -1) {
		memset(&vector, 0, sizeof(vector));
	}
	
	int target_word = cfg->rule_num / 64;
	int target_bit = 63 - (cfg->rule_num % 64);
	if (value)
		vector.word[target_word] |= (__u64)1 << target_bit;
	else
		vector.word[target_word] &= ~((__u64)1 << target_bit);
	if (bpf_map_update_elem(map_fd, &cfg->rule_key.ifindex, &vector, 0)) {
		fprintf(stderr, "ERR: Updating dev_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	return EXIT_OK;
}

int set_vectors(struct config *cfg, int value) {
	int err;
	err = set_src_ip_vector(cfg, value);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s src ip vector.\n", cfg->module_name);
		return err;
	}

	err = set_dst_ip_vector(cfg, value);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s dst ip vector.\n", cfg->module_name);
		return err;
	}


	if (cfg->rule_key.proto == IPPROTO_TCP || cfg->rule_key.proto == IPPROTO_UDP || cfg->rule_key.proto == 255) {
		err = set_sport_vector(cfg, value);
		if (err) {
			fprintf(stderr, "ERR: Updating module %s source port vector.\n", cfg->module_name);
			return err;
		}

		err = set_dport_vector(cfg, value);
		if (err) {
			fprintf(stderr, "ERR: Updating module %s dest port vector.\n", cfg->module_name);
			return err;
		}
	}

	if (cfg->rule_key.proto == IPPROTO_ICMP || cfg->rule_key.proto == IPPROTO_ICMPV6 || cfg->rule_key.proto == 255) {
		err = set_icmp_type_vector(cfg, value);
		if (err) {
			fprintf(stderr, "ERR: Updating module %s icmp type vector.\n", cfg->module_name);
			return err;
		}
	}

	err = set_dev_vector(cfg, value);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s device vector.\n", cfg->module_name);
		return err;
	}

	return EXIT_OK;
}

int add_rule(struct config *cfg, int isPolicy)
{
	int err, len;
	int rule_map_fd;
	int module_map_fd;
	int module_index;
	char map_path[PATH_MAX];
	struct rule_info rinfo = {
		.rule_key = cfg->rule_key,
		.action = cfg->rule_action,
		.jmp_index = cfg->jmp_index,
	};
	struct module_info minfo;

	// get module index
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_index", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_index map path.\n");
		return EXIT_FAIL_OPTION;
	}

	module_map_fd = bpf_obj_get(map_path);
	if (module_map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_info map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(module_map_fd, &cfg->module_name, &module_index)) {
		fprintf(stderr, "ERR: Reading module index.\n");
		return EXIT_FAIL_BPF;
	}

	if (module_index < 0) {
		fprintf(stderr, "ERR: Module '%s' not found.\n", cfg->module_name);
		return EXIT_FAIL_BPF;
	}

	if (!isPolicy) {
		// modules_info
		len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_info", pin_basedir);
		if (len < 0) {
			fprintf(stderr, "ERR: creating modules_info map path.\n");
			return EXIT_FAIL_OPTION;
		}

		module_map_fd = bpf_obj_get(map_path);
		if (module_map_fd < 0) {
			fprintf(stderr, "ERR: Opening modules_info map.\n");
			return EXIT_FAIL_BPF;
		}

		if (bpf_map_lookup_elem(module_map_fd, &module_index, &minfo)) {
			fprintf(stderr, "ERR: Reading modules info.\n");
			return EXIT_FAIL_BPF;
		}

		if (strcmp(minfo.module_name, cfg->module_name)) {
			fprintf(stderr, "ERR: Module name mismatch.\n");
			return EXIT_FAIL_OPTION;
		}

		if (minfo.rule_count >= MAX_RULE) {
			fprintf(stderr, "ERR: Module %s has reach maximum amount of rule.", cfg->module_name);
			return EXIT_FAIL_OPTION;
		}

		cfg->rule_num = minfo.rule_count;
	} else cfg->rule_num = POLICY_RULE;

	len = snprintf(map_path, PATH_MAX, "%s/%s/rules_info", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	rule_map_fd = bpf_obj_get(map_path);
	if (rule_map_fd < 0) {
		fprintf(stderr, "ERR: Opening rules_info map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_update_elem(rule_map_fd, &cfg->rule_num, &rinfo, 0)) {
		fprintf(stderr, "ERR: Updating rules info.\n");
		return EXIT_FAIL_BPF;
	}

	if (isPolicy)
		err = set_vectors(cfg, 0);
	else
		err = set_vectors(cfg, 1);

	if (err)
		return err;

	if (!isPolicy) {
		minfo.rule_count += 1;
		if (bpf_map_update_elem(module_map_fd, &module_index, &minfo, 0)) {
			fprintf(stderr, "ERR: Updating modules info.\n");
			return EXIT_FAIL_BPF;
		}
		printf("Rule successfully added to module %s at index %d.\n", cfg->module_name, cfg->rule_num);
	}

	return EXIT_OK;
}

int delete_src_ip_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 ipv4_key, ipv4_prev;
	struct in6_addr ipv6_key, ipv6_prev;
	union ipv4_lpm_key ipv4_lpm_key, ipv4_lpm_prev;
	union ipv6_lpm_key ipv6_lpm_key, ipv6_lpm_prev;
	struct rule_vector vector;
	struct rule_lpm_value lpm_val;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv4_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv4_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating src_ipv4_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening src_ipv4_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv4_key) == 0) {

		if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv4_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_prev = ipv4_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_prev, &ipv4_key) == 0) {

			if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'src_ipv4_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv4_prev = ipv4_key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'src_ipv4_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'src_ipv4_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, ipv4_lpm_key_size,
								sizeof(struct rule_lpm_value), MAX_RULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv4_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv4_lpm_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating src_ipv4_lpm_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening src_ipv4_lpm_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv4_lpm_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
			shift_left_vector(cfg->rule_num, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv4_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_lpm_prev = ipv4_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_lpm_prev, &ipv4_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
				shift_left_vector(cfg->rule_num, &lpm_val.vector);
				err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'src_ipv4_lpm_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv4_lpm_prev = ipv4_lpm_key;
		}

	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'src_ipv4_lpm_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'src_ipv4_lpm_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct in6_addr),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv6_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv6_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating src_ipv6_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening src_ipv6_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv6_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv6_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_prev = ipv6_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_prev, &ipv6_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'src_ipv6_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv6_prev = ipv6_key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'src_ipv6_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'src_ipv6_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, ipv6_lpm_key_size,
								sizeof(struct rule_lpm_value), MAX_RULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv6_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv6_lpm_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating src_ipv6_lpm_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening src_ipv6_lpm_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv6_lpm_key) == 0) {

		if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
			shift_left_vector(cfg->rule_num, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv6_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_lpm_prev = ipv6_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_lpm_prev, &ipv6_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
				shift_left_vector(cfg->rule_num, &lpm_val.vector);
				err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'src_ipv6_lpm_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv6_lpm_prev = ipv6_lpm_key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'src_ipv6_lpm_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'src_ipv6_lpm_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int delete_dst_ip_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 ipv4_key, ipv4_prev;
	struct in6_addr ipv6_key, ipv6_prev;
	union ipv4_lpm_key ipv4_lpm_key, ipv4_lpm_prev;
	union ipv6_lpm_key ipv6_lpm_key, ipv6_lpm_prev;
	struct rule_vector vector;
	struct rule_lpm_value lpm_val;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv4_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv4_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dst_ipv4_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dst_ipv4_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv4_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv4_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_prev = ipv4_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_prev, &ipv4_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dst_ipv4_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv4_prev = ipv4_key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dst_ipv4_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dst_ipv4_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, ipv4_lpm_key_size,
								sizeof(struct rule_lpm_value), MAX_RULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv4_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv4_lpm_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dst_ipv4_lpm_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dst_ipv4_lpm_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv4_lpm_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
			shift_left_vector(cfg->rule_num, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv4_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_lpm_prev = ipv4_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_lpm_prev, &ipv4_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
				shift_left_vector(cfg->rule_num, &lpm_val.vector);
				err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dst_ipv4_lpm_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv4_lpm_prev = ipv4_lpm_key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dst_ipv4_lpm_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dst_ipv4_lpm_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct in6_addr),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv6_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv6_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dst_ipv6_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dst_ipv6_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv6_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv6_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_prev = ipv6_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_prev, &ipv6_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dst_ipv6_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv6_prev = ipv6_key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dst_ipv6_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dst_ipv6_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, ipv6_lpm_key_size,
								sizeof(struct rule_lpm_value), MAX_RULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv6_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv6_lpm_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dst_ipv6_lpm_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dst_ipv6_lpm_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv6_lpm_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
			shift_left_vector(cfg->rule_num, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv6_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_lpm_prev = ipv6_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_lpm_prev, &ipv6_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
				shift_left_vector(cfg->rule_num, &lpm_val.vector);
				err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dst_ipv6_lpm_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv6_lpm_prev = ipv6_lpm_key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dst_ipv6_lpm_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dst_ipv6_lpm_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int delete_sport_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u16 key, prev_key;
	struct rule_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'tcp_sport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/tcp_sport_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating tcp_sport_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening tcp_sport_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'tcp_sport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'tcp_sport_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'tcp_sport_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'tcp_sport_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'udp_sport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/udp_sport_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating udp_sport_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening udp_sport_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'udp_sport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'udp_sport_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'udp_sport_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'udp_sport_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int delete_dport_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u16 key, prev_key;
	struct rule_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'tcp_dport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/tcp_dport_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating tcp_dport_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening tcp_dport_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'tcp_dport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'tcp_dport_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'tcp_dport_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'tcp_dport_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'udp_dport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/udp_dport_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating udp_dport_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening udp_dport_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd,NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'udp_dport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'udp_dport_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'udp_dport_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'udp_dport_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int delete_icmp_type_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u8 key, prev_key;
	struct rule_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u8),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'icmp_type_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/icmp_type_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating icmp_type_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening icmp_type_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'icmp_type_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'icmp_type_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'icmp_type_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'icmp_type_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u8),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'icmpv6_type_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/icmpv6_type_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating icmpv6_type_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening icmpv6_type_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd,NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'icmpv6_type_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'icmpv6_type_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'icmpv6_type_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'icmpv6_type_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int delete_dev_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 key, prev_key;
	struct rule_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dev_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dev_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dev_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dev_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_left_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dev_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dev_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dev_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dev_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int delete_vectors(struct config *cfg) {
	int err;
	err = delete_src_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s src ip vector.\n", cfg->module_name);
		return err;
	}

	err = delete_dst_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s dst ip vector.\n", cfg->module_name);
		return err;
	}

	err = delete_sport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s source port vector.\n", cfg->module_name);
		return err;
	}

	err = delete_dport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s dest port vector.\n", cfg->module_name);
		return err;
	}

	err = delete_icmp_type_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s icmp type vector.\n", cfg->module_name);
		return err;
	}

	err = delete_dev_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s device vector.\n", cfg->module_name);
		return err;
	}

	return EXIT_OK;
}

int delete_rule(struct config *cfg)
{
	int err, len;
	int rule_map_fd;
	int module_map_fd;
	int stats_map_fd;
	int module_index;
	char map_path[PATH_MAX];
	struct rule_info rinfo;
	struct module_info minfo;
	int nr_cpus = libbpf_num_possible_cpus();
	struct stats_rec rec[nr_cpus];

	// get module index
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_index", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_index map path.\n");
		return EXIT_FAIL_OPTION;
	}

	module_map_fd = bpf_obj_get(map_path);
	if (module_map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_index map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(module_map_fd, &cfg->module_name, &module_index)) {
		fprintf(stderr, "ERR: Reading module index.\n");
		return EXIT_FAIL_BPF;
	}

	if (module_index < 0) {
		fprintf(stderr, "ERR: Module '%s' not found.\n", cfg->module_name);
		return EXIT_FAIL_BPF;
	}

	// modules_info
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}
	module_map_fd = bpf_obj_get(map_path);
	if (module_map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_info map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_lookup_elem(module_map_fd, &module_index, &minfo)) {
		fprintf(stderr, "ERR: Reading modules info.\n");
		return EXIT_FAIL_BPF;
	}

	if (strcmp(minfo.module_name, cfg->module_name)) {
		fprintf(stderr, "ERR: Module name mismatch.\n");
		return EXIT_FAIL_OPTION;
	}

	if (minfo.rule_count == 0) {
		fprintf(stderr, "ERR: No rule in module %s.\n", cfg->module_name);
		return EXIT_FAIL_OPTION;
	}

	if (minfo.rule_count <= cfg->rule_num || cfg->rule_num < 0 || cfg->rule_num >= MAX_RULE) {
		fprintf(stderr, "ERR: rule number %d not available. (number 1 - %d are available)\n", cfg->rule_num+1, minfo.rule_count);
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rules_info", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	rule_map_fd = bpf_obj_get(map_path);
	if (rule_map_fd < 0) {
		fprintf(stderr, "ERR: Opening rules_info map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rule_stats", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rule_stats map path.\n");
		return EXIT_FAIL_OPTION;
	}

	stats_map_fd = bpf_obj_get(map_path);
	if (stats_map_fd < 0) {
		fprintf(stderr, "ERR: Opening rule_stats map path.\n");
		return EXIT_FAIL_BPF;
	}

	int new_rule_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32),
										sizeof(struct rule_info), MAX_RULE_ENTRIES, 0);
	if (new_rule_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'rules_info' map\n");
		return EXIT_FAIL_BPF;
	}

	int new_stats_map_fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(__u32),
										sizeof(struct stats_rec), MAX_RULE_ENTRIES, 0);
	if (new_stats_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'rule_stats' map\n");
		return EXIT_FAIL_BPF;
	}

	err = delete_vectors(cfg);
	if (err)
		return err;

	int i;
	for (i=0; i<minfo.rule_count; i++) {
		if (i == cfg->rule_num) continue;
		int new_index = i;
		if (i > cfg->rule_num) new_index--;
		if (bpf_map_lookup_elem(rule_map_fd, &i, &rinfo)) {
			fprintf(stderr, "ERR: Reading old 'rules_info' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_update_elem(new_rule_map_fd, &new_index, &rinfo, 0)) {
			fprintf(stderr, "ERR: Updating new 'rules_info' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_lookup_elem(stats_map_fd, &i, &rec)) {
			fprintf(stderr, "ERR: Reading old 'rule_stats' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_update_elem(new_stats_map_fd, &new_index, &rec, 0)) {
			fprintf(stderr, "ERR: Updating new 'rule_stats' map.\n");
			return EXIT_FAIL_BPF;
		}
	}

	i = POLICY_RULE;
	if (bpf_map_lookup_elem(rule_map_fd, &i, &rinfo)) {
		fprintf(stderr, "ERR: Reading old 'rules_info' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_update_elem(new_rule_map_fd, &i, &rinfo, 0)) {
		fprintf(stderr, "ERR: Updating new 'rules_info' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_lookup_elem(stats_map_fd, &i, &rec)) {
		fprintf(stderr, "ERR: Reading old 'rule_stats' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_update_elem(new_stats_map_fd, &i, &rec, 0)) {
		fprintf(stderr, "ERR: Updating new 'rule_stats' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rules_info", pin_basedir, cfg->module_name);
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'rules_info' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_rule_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'rules_info' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rule_stats", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rule_stats map path.\n");
		return EXIT_FAIL_OPTION;
	}
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'rule_stats' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_stats_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'rule_stats' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	struct config loader_cfg = {
		.cmd		= ADD_MODULE,
		.module_index 	= module_index,
		.reuse_maps = 1,
	};

	strncpy(loader_cfg.module_name, cfg->module_name, MAX_MODULE_NAME);
	err = module_loader(&loader_cfg, -1);
	if (err) {
		fprintf(stderr, "ERR: Reloading module '%s'.\n", cfg->module_name);
		return err;
	}

	minfo.rule_count = minfo.rule_count - 1;
	if(bpf_map_update_elem(module_map_fd, &module_index, &minfo, 0)) {
		fprintf(stderr, "ERR: Updating Module info.\n");
		return EXIT_FAIL_BPF;
	}

	return EXIT_OK;
}

int insert_src_ip_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 ipv4_key, ipv4_prev;
	struct in6_addr ipv6_key, ipv6_prev;
	union ipv4_lpm_key ipv4_lpm_key, ipv4_lpm_prev;
	union ipv6_lpm_key ipv6_lpm_key, ipv6_lpm_prev;
	struct rule_vector vector;
	struct rule_lpm_value lpm_val;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv4_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv4_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating src_ipv4_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening src_ipv4_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv4_key) == 0) {

		if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv4_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_prev = ipv4_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_prev, &ipv4_key) == 0) {

			if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'src_ipv4_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv4_prev = ipv4_key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'src_ipv4_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'src_ipv4_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, ipv4_lpm_key_size,
								sizeof(struct rule_lpm_value), MAX_RULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv4_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv4_lpm_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating src_ipv4_lpm_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening src_ipv4_lpm_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv4_lpm_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
			shift_right_vector(cfg->rule_num, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv4_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_lpm_prev = ipv4_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_lpm_prev, &ipv4_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
				shift_right_vector(cfg->rule_num, &lpm_val.vector);
				err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'src_ipv4_lpm_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv4_lpm_prev = ipv4_lpm_key;
		}

	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'src_ipv4_lpm_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'src_ipv4_lpm_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct in6_addr),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv6_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv6_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating src_ipv6_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening src_ipv6_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv6_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv6_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_prev = ipv6_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_prev, &ipv6_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'src_ipv6_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv6_prev = ipv6_key;
		}
	}

	

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'src_ipv6_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'src_ipv6_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, ipv6_lpm_key_size,
								sizeof(struct rule_lpm_value), MAX_RULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv6_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/src_ipv6_lpm_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating src_ipv6_lpm_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening src_ipv6_lpm_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv6_lpm_key) == 0) {

		if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
			shift_right_vector(cfg->rule_num, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv6_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_lpm_prev = ipv6_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_lpm_prev, &ipv6_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
				shift_right_vector(cfg->rule_num, &lpm_val.vector);
				err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'src_ipv6_lpm_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv6_lpm_prev = ipv6_lpm_key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'src_ipv6_lpm_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'src_ipv6_lpm_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int insert_dst_ip_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 ipv4_key, ipv4_prev;
	struct in6_addr ipv6_key, ipv6_prev;
	union ipv4_lpm_key ipv4_lpm_key, ipv4_lpm_prev;
	union ipv6_lpm_key ipv6_lpm_key, ipv6_lpm_prev;
	struct rule_vector vector;
	struct rule_lpm_value lpm_val;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv4_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv4_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dst_ipv4_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dst_ipv4_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv4_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv4_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_prev = ipv4_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_prev, &ipv4_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dst_ipv4_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv4_prev = ipv4_key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dst_ipv4_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dst_ipv4_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, ipv4_lpm_key_size,
								sizeof(struct rule_lpm_value), MAX_RULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv4_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv4_lpm_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dst_ipv4_lpm_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dst_ipv4_lpm_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv4_lpm_key) == 0) {

		if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
			shift_right_vector(cfg->rule_num, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv4_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_lpm_prev = ipv4_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_lpm_prev, &ipv4_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
				shift_right_vector(cfg->rule_num, &lpm_val.vector);
				err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dst_ipv4_lpm_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv4_lpm_prev = ipv4_lpm_key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dst_ipv4_lpm_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dst_ipv4_lpm_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(struct in6_addr),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv6_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv6_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dst_ipv6_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dst_ipv6_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv6_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv6_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_prev = ipv6_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_prev, &ipv6_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dst_ipv6_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv6_prev = ipv6_key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dst_ipv6_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dst_ipv6_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_LPM_TRIE, ipv6_lpm_key_size,
								sizeof(struct rule_lpm_value), MAX_RULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv6_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dst_ipv6_lpm_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dst_ipv6_lpm_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dst_ipv6_lpm_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &ipv6_lpm_key) == 0) {

		if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
			shift_right_vector(cfg->rule_num, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv6_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_lpm_prev = ipv6_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_lpm_prev, &ipv6_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
				shift_right_vector(cfg->rule_num, &lpm_val.vector);
				err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dst_ipv6_lpm_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			ipv6_lpm_prev = ipv6_lpm_key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dst_ipv6_lpm_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dst_ipv6_lpm_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int insert_sport_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u16 key, prev_key;
	struct rule_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'tcp_sport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/tcp_sport_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating tcp_sport_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening tcp_sport_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'tcp_sport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'tcp_sport_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'tcp_sport_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'tcp_sport_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'udp_sport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/udp_sport_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating udp_sport_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening udp_sport_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'udp_sport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'udp_sport_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'udp_sport_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'udp_sport_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int insert_dport_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u16 key, prev_key;
	struct rule_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'tcp_dport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/tcp_dport_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating tcp_dport_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening tcp_dport_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'tcp_dport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'tcp_dport_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'tcp_dport_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'tcp_dport_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'udp_dport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/udp_dport_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating udp_dport_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening udp_dport_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'udp_dport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'udp_dport_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'udp_dport_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'udp_dport_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int insert_icmp_type_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u8 key, prev_key;
	struct rule_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u8),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'icmp_type_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/icmp_type_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating icmp_type_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening icmp_type_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'icmp_type_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'icmp_type_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}


	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'icmp_type_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'icmp_type_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u8),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'icmpv6_type_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/icmpv6_type_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating icmpv6_type_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening icmpv6_type_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'icmpv6_type_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'icmpv6_type_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'icmpv6_type_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'icmpv6_type_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int insert_dev_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 key, prev_key;
	struct rule_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct rule_vector), MAX_RULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dev_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/dev_vector", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating dev_vector map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening dev_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
			shift_right_vector(cfg->rule_num, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dev_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_vector(cfg->rule_num, &vector);
				err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
				if (err) {
					fprintf(stderr, "ERR: Updating new 'dev_vector' map.\n");
					return EXIT_FAIL_BPF;
				}
			}
			prev_key = key;
		}

	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'dev_vector' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'dev_vector' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	close(map_fd);
	close(new_map_fd);

	return EXIT_OK;
}

int insert_vectors(struct config *cfg) {
	int err;
	err = insert_src_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s src ip vector.\n", cfg->module_name);
		return err;
	}

	err = insert_dst_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s dst ip vector.\n", cfg->module_name);
		return err;
	}

	err = insert_sport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s source port vector.\n", cfg->module_name);
		return err;
	}

	err = insert_dport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s dest port vector.\n", cfg->module_name);
		return err;
	}

	err = insert_icmp_type_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s icmp type vector.\n", cfg->module_name);
		return err;
	}

	err = insert_dev_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s device vector.\n", cfg->module_name);
		return err;
	}

	err = set_vectors(cfg, 1);
	if (err)
		return err;

	return EXIT_OK;
}

int insert_rule(struct config *cfg)
{
	int err, len;
	int rule_map_fd;
	int module_map_fd;
	int stats_map_fd;
	int module_index;
	char map_path[PATH_MAX];
	struct rule_info rinfo = {
		.rule_key = cfg->rule_key,
		.action = cfg->rule_action,
		.jmp_index = cfg->jmp_index,
	};
	struct module_info minfo;
	int nr_cpus = libbpf_num_possible_cpus();
	struct stats_rec rec[nr_cpus];

	// get module index
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_index", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_index map path.\n");
		return EXIT_FAIL_OPTION;
	}

	module_map_fd = bpf_obj_get(map_path);
	if (module_map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_index map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(module_map_fd, &cfg->module_name, &module_index)) {
		fprintf(stderr, "ERR: Reading module index.\n");
		return EXIT_FAIL_BPF;
	}

	if (module_index < 0) {
		fprintf(stderr, "ERR: Module '%s' not found.\n", cfg->module_name);
		return EXIT_FAIL_BPF;
	}

	// modules_info
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}
	module_map_fd = bpf_obj_get(map_path);
	if (module_map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_info map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_lookup_elem(module_map_fd, &module_index, &minfo)) {
		fprintf(stderr, "ERR: Reading modules info.\n");
		return EXIT_FAIL_BPF;
	}

	if (strcmp(minfo.module_name, cfg->module_name)) {
		fprintf(stderr, "ERR: Module name mismatch.\n");
		return EXIT_FAIL_OPTION;
	}

	if (minfo.rule_count >= MAX_RULE) {
		fprintf(stderr, "ERR: Module %s has reach maximum amount of rule.", cfg->module_name);
		return EXIT_FAIL_OPTION;
	}

	if (cfg->rule_num >= minfo.rule_count) {
		printf("WARN: Module %s has only %d rules. This rule would be appended to module instead.\n", cfg->module_name, minfo.rule_count);
		err = add_rule(cfg, 0);
		return err;
	}

	if (cfg->rule_num < 0 || cfg->rule_num >= MAX_RULE) {
		fprintf(stderr, "ERR: Invalid rule index (index=%d).\n", cfg->rule_num);
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rules_info", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	rule_map_fd = bpf_obj_get(map_path);
	if (rule_map_fd < 0) {
		fprintf(stderr, "ERR: Opening rules_info map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rule_stats", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rule_stats map path.\n");
		return EXIT_FAIL_OPTION;
	}

	stats_map_fd = bpf_obj_get(map_path);
	if (stats_map_fd < 0) {
		fprintf(stderr, "ERR: Opening rule_stats map path.\n");
		return EXIT_FAIL_BPF;
	}

	int new_rule_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32),
										sizeof(struct rule_info), MAX_RULE_ENTRIES, 0);
	if (new_rule_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'rules_info' map\n");
		return EXIT_FAIL_BPF;
	}

	int new_stats_map_fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(__u32),
										sizeof(struct stats_rec), MAX_RULE_ENTRIES, 0);
	if (new_stats_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'rule_stats' map\n");
		return EXIT_FAIL_BPF;
	}

	err = insert_vectors(cfg);
	if (err)
		return err;

	int i;
	for (i=minfo.rule_count; i>=0; i--) {
		int new_index = i;
		if (i >= cfg->rule_num) new_index++;
		if (bpf_map_lookup_elem(rule_map_fd, &i, &rinfo)) {
			fprintf(stderr, "ERR: Reading old 'rules_info' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_update_elem(new_rule_map_fd, &new_index, &rinfo, 0)) {
			fprintf(stderr, "ERR: Updating new 'rules_info' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_lookup_elem(stats_map_fd, &i, &rec)) {
			fprintf(stderr, "ERR: Reading old 'rule_stats' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_update_elem(new_stats_map_fd, &new_index, &rec, 0)) {
			fprintf(stderr, "ERR: Updating new 'rule_stats' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (i == cfg->rule_num) {
			struct rule_info new_rinfo = {
				.rule_key = cfg->rule_key,
				.action = cfg->rule_action,
				.jmp_index = cfg->jmp_index,
			};
			if (bpf_map_update_elem(new_rule_map_fd, &i, &new_rinfo, 0)) {
				fprintf(stderr, "ERR: Updating new 'rules_info' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
	}

	i = POLICY_RULE;
	if (bpf_map_lookup_elem(rule_map_fd, &i, &rinfo)) {
		fprintf(stderr, "ERR: Reading old 'rules_info' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_update_elem(new_rule_map_fd, &i, &rinfo, 0)) {
		fprintf(stderr, "ERR: Updating new 'rules_info' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_lookup_elem(stats_map_fd, &i, &rec)) {
		fprintf(stderr, "ERR: Reading old 'rule_stats' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_update_elem(new_stats_map_fd, &i, &rec, 0)) {
		fprintf(stderr, "ERR: Updating new 'rule_stats' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rules_info", pin_basedir, cfg->module_name);
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'rules_info' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_rule_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'rules_info' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rule_stats", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rule_stats map path.\n");
		return EXIT_FAIL_OPTION;
	}
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'rule_stats' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_stats_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'rule_stats' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	struct config loader_cfg = {
		.cmd		= ADD_MODULE,
		.module_index 	= module_index,
		.reuse_maps = 1,
	};

	strncpy(loader_cfg.module_name, cfg->module_name, MAX_MODULE_NAME);
	err = module_loader(&loader_cfg, -1);
	if (err) {
		fprintf(stderr, "ERR: Reloading module '%s'.\n", cfg->module_name);
		return err;
	}

	minfo.rule_count = minfo.rule_count + 1;
	if(bpf_map_update_elem(module_map_fd, &module_index, &minfo, 0)) {
		fprintf(stderr, "ERR: Updating Module info.\n");
		return EXIT_FAIL_BPF;
	}

	return EXIT_OK;
}

int list_rules(struct config *cfg) {
	int len;
	int index = 0;
	int module_index = 0;
	int module_map_fd;
	int rule_map_fd;
	int index_map_fd;
	int stats_map_fd;
	char map_path[PATH_MAX];
	struct module_info minfo;
	struct rule_info rinfo;

	// get module index
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_index", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_index map path.\n");
		return EXIT_FAIL_OPTION;
	}

	index_map_fd = bpf_obj_get(map_path);
	if (index_map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_index map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(index_map_fd, &cfg->module_name, &module_index)) {
		fprintf(stderr, "ERR: Reading module index.\n");
		return EXIT_FAIL_BPF;
	}

	if (module_index < 0) {
		fprintf(stderr, "ERR: Module '%s' not found.\n", cfg->module_name);
		return EXIT_FAIL_BPF;
	}

	// modules_info
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}
	module_map_fd = bpf_obj_get(map_path);
	if (module_map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_info map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(module_map_fd, &module_index, &minfo)) {
		fprintf(stderr, "ERR: Reading module info\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rules_info", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	rule_map_fd = bpf_obj_get(map_path);
	if (rule_map_fd < 0) {
		fprintf(stderr, "ERR: Opening rules_info map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rule_stats", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rule_stats map path.\n");
		return EXIT_FAIL_OPTION;
	}
	stats_map_fd = bpf_obj_get(map_path);
	if (module_map_fd < 0) {
		fprintf(stderr, "ERR: Opening rule_stats map.\n");
		return EXIT_FAIL_BPF;
	}

	index = POLICY_RULE;
	if (bpf_map_lookup_elem(rule_map_fd, &index, &rinfo)) {
		fprintf(stderr, "ERR: Reading rule info\n");
		return EXIT_FAIL_BPF;
	}

	printf("================================================================================================================================\n");
	printf("XDP Modular Firewall | Module Name: %s", minfo.module_name);
	printf("\n--------------------------------------------------------------------------------------------------------------------------------\n");
	printf("STATUS: ");
	if (minfo.operating)
		printf("%8s", "ACTIVE");
	else
		printf("%8s", "INACTIVE");
	printf(" | Rule Count: %5d | POLICY: ", minfo.rule_count);
	if (rinfo.action == XDP_PASS)
		printf("ACCEPT");
	else if (rinfo.action == XDP_DROP)
		printf("REJECT");
	else if (rinfo.action == XDP_REDIRECT)
		printf("JUMP[%d]", rinfo.jmp_index+1);

	printf("\n================================================================================================================================\n");
	printf("  NO.\tSOURCE\t\tDEST\t\tPROT\tDEV\t\t\tACTION%16s%16s", "MATCH PKTS", "MATCH BYTES");
	printf("\n--------------------------------------------------------------------------------------------------------------------------------\n");

	for (index=0; index<minfo.rule_count; index++) {
		if (bpf_map_lookup_elem(rule_map_fd, &index, &rinfo) >= 0) {
			printf("%5d\t", index+1);
			print_rulekey(&rinfo.rule_key);
			if (rinfo.action == XDP_PASS)
				printf("ACCEPT");
			else if (rinfo.action == XDP_DROP)
				printf("REJECT");
			else if (rinfo.action == XDP_REDIRECT)
				printf("JUMP[%d]", rinfo.jmp_index+1);
			print_stats(stats_map_fd, index);
			printf("\n");
		}
	}
	printf("\n");

	return EXIT_OK;
}

int set_policy(struct config *cfg)
{
	int len;
	int rule_map_fd;
	int module_map_fd;
	int module_index;
	char map_path[PATH_MAX];
	struct rule_info rinfo;
	cfg->rule_num = POLICY_RULE;

	// get module index
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_index", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_index map path.\n");
		return EXIT_FAIL_OPTION;
	}

	module_map_fd = bpf_obj_get(map_path);
	if (module_map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_index map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(module_map_fd, &cfg->module_name, &module_index)) {
		fprintf(stderr, "ERR: Reading module index.\n");
		return EXIT_FAIL_BPF;
	}

	if (module_index < 0) {
		fprintf(stderr, "ERR: Module '%s' not found.\n", cfg->module_name);
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s/rules_info", pin_basedir, cfg->module_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating rules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	rule_map_fd = bpf_obj_get(map_path);
	if (rule_map_fd < 0) {
		fprintf(stderr, "ERR: Opening rules_info map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(rule_map_fd, &cfg->rule_num, &rinfo)) {
		fprintf(stderr, "ERR: Reading policy.\n");
		return EXIT_FAIL_BPF;
	}

	rinfo.action = cfg->rule_action;
	rinfo.jmp_index = cfg->jmp_index;

	if (bpf_map_update_elem(rule_map_fd, &cfg->rule_num, &rinfo, 0)) {
		fprintf(stderr, "ERR: Updating policy.\n");
		return EXIT_FAIL_BPF;
	}

	return EXIT_OK;
}

#endif