#ifndef __MODULE_MANAGEMENT_HELPERS_H
#define __MODULE_MANAGEMENT_HELPERS_H

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
#include "loader_helpers.h"
#include "rule_mgmt_helpers.h"
#include "common_mgmt_helpers.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

void shift_right_class_vector(int index, struct class_vector *vector) {

	__u64 val = 0;
	int target_word = index / 64;
	int target_bit = 63 - (index % 64);
	int i;

	for (i=target_word; i<MAX_CLASS_WORD; i++) {
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

void shift_left_class_vector(int index, struct class_vector *vector) {

	__u64 val = 0;
	int target_word = index / 64;
	int target_bit = 63 - (index % 64);
	int i;

	for (i=MAX_CLASS_WORD-1; i>=target_word; i--) {
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

int set_classifier_src_ip_vector(struct config *cfg, int value) {
	
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct class_vector vector;
	struct class_lpm_value lpm_val;

	switch (cfg->rule_key.AF) {
		case 0:
		case AF_INET: {
			if (cfg->rule_key.src_ipv4 != 0x00000000) {
				len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv4_vector", pin_basedir);
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

				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);

				if (value)
					vector.word[target_word] |= (__u64)1 << target_bit;
				else
					vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.src_ipv4, &vector, 0)) {
					fprintf(stderr, "ERR: Updating src_ipv4_vector map.\n");
					return EXIT_FAIL_BPF;
				}
			} else {
				len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv4_lpm_vector", pin_basedir);
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);

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
				len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv6_vector", pin_basedir);
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				if (value)
					vector.word[target_word] |= (__u64)1 << target_bit;
				else
					vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.src_ipv6, &vector, 0)) {
					fprintf(stderr, "ERR: Updating src_ipv6_vector map.\n");
					return EXIT_FAIL_BPF;
				}
			} else {
				len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv6_lpm_vector", pin_basedir);
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
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

int set_classifier_dst_ip_vector(struct config *cfg, int value) {

	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct class_vector vector;
	struct class_lpm_value lpm_val;

	switch (cfg->rule_key.AF) {
		case 0:
		case AF_INET: {
			if (cfg->rule_key.dst_ipv4 != 0x00000000) {
				len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv4_vector", pin_basedir);
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				if (value)
					vector.word[target_word] |= (__u64)1 << target_bit;
				else
					vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.dst_ipv4, &vector, 0)) {
					fprintf(stderr, "ERR: Updating dst_ipv4_vector map.\n");
					return EXIT_FAIL_BPF;
				}
			} else {
				len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv4_lpm_vector", pin_basedir);
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
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
				len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv6_vector", pin_basedir);
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				if (value)
					vector.word[target_word] |= (__u64)1 << target_bit;
				else
					vector.word[target_word] &= ~((__u64)1 << target_bit);

				if (bpf_map_update_elem(map_fd, &cfg->rule_key.dst_ipv6, &vector, 0)) {
					fprintf(stderr, "ERR: Updating dst_ipv6_vector map.\n");
					return EXIT_FAIL_BPF;
				}
			} else {
				len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv6_lpm_vector", pin_basedir);
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
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

int set_classifier_sport_vector(struct config *cfg, int value) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct class_vector vector;

	switch (cfg->rule_key.proto) {
		case 255:
		case IPPROTO_TCP: {
			len = snprintf(map_path, PATH_MAX, "%s/classifier/tcp_sport_vector", pin_basedir);
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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
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
			len = snprintf(map_path, PATH_MAX, "%s/classifier/udp_sport_vector", pin_basedir);
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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
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

int set_classifier_dport_vector(struct config *cfg, int value) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct class_vector vector;

	switch (cfg->rule_key.proto) {
		case 255:
		case IPPROTO_TCP: {
			len = snprintf(map_path, PATH_MAX, "%s/classifier/tcp_dport_vector", pin_basedir);
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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
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
			len = snprintf(map_path, PATH_MAX, "%s/classifier/udp_dport_vector", pin_basedir);
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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
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

int set_classifier_icmp_type_vector(struct config *cfg, int value) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct class_vector vector;

	switch (cfg->rule_key.proto) {
		case 255:
		case IPPROTO_ICMP: {
			len = snprintf(map_path, PATH_MAX, "%s/classifier/icmp_type_vector", pin_basedir);
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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
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
			len = snprintf(map_path, PATH_MAX, "%s/classifier/icmpv6_type_vector", pin_basedir);
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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
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

int set_classifier_dev_vector(struct config *cfg, int value) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct class_vector vector;

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dev_vector", pin_basedir);
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
	
	int target_word = cfg->new_index / 64;
	int target_bit = 63 - (cfg->new_index % 64);
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

int set_classifier_vectors(struct config *cfg, int value) {
	int err;
	err = set_classifier_src_ip_vector(cfg, value);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier src ip vector.\n");
		return err;
	}

	err = set_classifier_dst_ip_vector(cfg, value);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier dst ip vector.\n");
		return err;
	}

	if (cfg->rule_key.proto == IPPROTO_TCP || cfg->rule_key.proto == IPPROTO_UDP || cfg->rule_key.proto == 255) {
		err = set_classifier_sport_vector(cfg, value);
		if (err) {
			fprintf(stderr, "ERR: Updating classifier source port vector.\n");
			return err;
		}

		err = set_classifier_dport_vector(cfg, value);
		if (err) {
			fprintf(stderr, "ERR: Updating classifier dest port vector.\n");
			return err;
		}
	}

	if (cfg->rule_key.proto == IPPROTO_ICMP || cfg->rule_key.proto == IPPROTO_ICMPV6 || cfg->rule_key.proto == 255) {
		err = set_classifier_icmp_type_vector(cfg, value);
		if (err) {
			fprintf(stderr, "ERR: Updating classifier icmp type vector.\n");
			return err;
		}
	}

	err = set_classifier_dev_vector(cfg, value);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier device vector.\n");
		return err;
	}

	return EXIT_OK;
}

int add_module(struct config *cfg, int isMain)
{
	int err, len;
	int map_fd;
	int fw_map_fd;
	int index = 0;
	int module_index;
	char map_path[PATH_MAX];
	struct module_info info = {
		.rule_count = 0,
		.operating = 1,
		.key = cfg->rule_key,
	};

	cfg->reuse_maps = 0;

	strncpy(info.module_name, cfg->module_new_name, MAX_MODULE_NAME);

	if (!isMain) {
		len = snprintf(map_path, PATH_MAX, "%s/classifier/firewall_info", pin_basedir);
		if (len < 0) {
			fprintf(stderr, "ERR: creating firewall_info map path.\n");
			return EXIT_FAIL_OPTION;
		}

		fw_map_fd = bpf_obj_get(map_path);
		if (fw_map_fd < 0) {
			fprintf(stderr, "ERR: creating firewall_info map path.\n");
			return EXIT_FAIL_BPF;
		}

		if (bpf_map_lookup_elem(fw_map_fd, &index, &module_index)) {
			fprintf(stderr, "ERR: Reading firewall info.\n");
			return EXIT_FAIL_BPF;
		}

		if (module_index < 0 || module_index >= MAX_MODULE) {
			fprintf(stderr, "ERR: Invalid module index (index=%d).\n", module_index);
			return EXIT_FAIL_OPTION;
		}

		cfg->new_index = module_index;
	} else {
		module_index = MAIN_MODULE;
		cfg->new_index = module_index;
	}

	err = module_loader(cfg, -1);
	if (err) {
		return err;
	}

	// modules_info
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_info map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_update_elem(map_fd, &cfg->new_index, &info, 0)) {
		fprintf(stderr, "ERR: Error updating module info.\n");
		return EXIT_FAIL_BPF;
	}

	// modules_index
	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_index", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_index map path.\n");
		return EXIT_FAIL_OPTION;
	}

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		fprintf(stderr, "ERR: Opening modules_index map.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_update_elem(map_fd, &cfg->module_new_name, &cfg->new_index, 0)) {
		fprintf(stderr, "ERR: Error updating module index.\n");
		return EXIT_FAIL_BPF;
	}

	if (isMain)
		err = set_classifier_vectors(cfg, 0);
	else
		err = set_classifier_vectors(cfg, 1);

	if (err)
		return err;

	if (!isMain) {
		module_index += 1;
		if (bpf_map_update_elem(fw_map_fd, &index, &module_index, 0)) {
			fprintf(stderr, "ERR: Updating firewall info.\n");
			return EXIT_FAIL_BPF;
		}
	}
	

	struct config policy_cfg = {
		.rule_key	= {
			.AF			= 0,
			.src_ipv4	= 0x00000000,
			.dst_ipv4	= 0x00000000,
			.src_ipv6	= IN6ADDR_ANY_INIT,
			.dst_ipv6	= IN6ADDR_ANY_INIT,
			.src_ipv4_lpm = { },
			.dst_ipv4_lpm = { },
			.src_ipv6_lpm = { },
			.dst_ipv6_lpm = { },
			.proto		= 255,
			.sport		= 0,
			.dport		= 0,
			.icmp_type	= 255,
			.ifindex	= 0,
		},
		.rule_action = cfg->rule_action,
	};

	strncpy(policy_cfg.module_name, cfg->module_new_name, MAX_MODULE_NAME);

	err = add_rule(&policy_cfg, 1);
	if (err) {
		fprintf(stderr, "ERR: Initialize %s policy.\n", policy_cfg.module_name);
		return err;
	}

	printf("Module '%s' successfully added to firewall at index %d.\n", cfg->module_new_name, cfg->new_index);
	return EXIT_OK;
}

int delete_classifier_src_ip_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 ipv4_key, ipv4_prev;
	struct in6_addr ipv6_key, ipv6_prev;
	union ipv4_lpm_key ipv4_lpm_key, ipv4_lpm_prev;
	union ipv6_lpm_key ipv6_lpm_key, ipv6_lpm_prev;
	struct class_vector vector;
	struct class_lpm_value lpm_val;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv4_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv4_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv4_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_prev = ipv4_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_prev, &ipv4_key) == 0) {

			if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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
								sizeof(struct class_lpm_value), MAX_MODULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv4_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv4_lpm_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv4_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_lpm_prev = ipv4_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_lpm_prev, &ipv4_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
				shift_left_class_vector(cfg->index, &lpm_val.vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv6_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv6_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv6_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_prev = ipv6_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_prev, &ipv6_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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
								sizeof(struct class_lpm_value), MAX_MODULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv6_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv6_lpm_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv6_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_lpm_prev = ipv6_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_lpm_prev, &ipv6_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
				shift_left_class_vector(cfg->index, &lpm_val.vector);
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

int delete_classifier_dst_ip_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 ipv4_key, ipv4_prev;
	struct in6_addr ipv6_key, ipv6_prev;
	union ipv4_lpm_key ipv4_lpm_key, ipv4_lpm_prev;
	union ipv6_lpm_key ipv6_lpm_key, ipv6_lpm_prev;
	struct class_vector vector;
	struct class_lpm_value lpm_val;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv4_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv4_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv4_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_prev = ipv4_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_prev, &ipv4_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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
								sizeof(struct class_lpm_value), MAX_MODULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv4_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv4_lpm_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv4_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_lpm_prev = ipv4_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_lpm_prev, &ipv4_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
				shift_left_class_vector(cfg->index, &lpm_val.vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv6_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv6_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv6_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_prev = ipv6_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_prev, &ipv6_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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
								sizeof(struct class_lpm_value), MAX_MODULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv6_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv6_lpm_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv6_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_lpm_prev = ipv6_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_lpm_prev, &ipv6_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
				shift_left_class_vector(cfg->index, &lpm_val.vector);
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

int delete_classifier_sport_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u16 key, prev_key;
	struct class_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'tcp_sport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/tcp_sport_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'tcp_sport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'udp_sport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/udp_sport_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'udp_sport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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

int delete_classifier_dport_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u16 key, prev_key;
	struct class_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'tcp_dport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/tcp_dport_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'tcp_dport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'udp_dport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/udp_dport_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'udp_dport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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

int delete_classifier_icmp_type_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u8 key, prev_key;
	struct class_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u8),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'icmp_type_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/icmp_type_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'icmp_type_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'icmpv6_type_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/icmpv6_type_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'icmpv6_type_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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

int delete_classifier_dev_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 key, prev_key;
	struct class_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dev_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dev_vector", pin_basedir);
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
			shift_left_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dev_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_left_class_vector(cfg->index, &vector);
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

int delete_classifier_vectors(struct config *cfg) {
	int err;
	err = delete_classifier_src_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier src ip vector.\n");
		return err;
	}

	err = delete_classifier_dst_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier dst ip vector.\n");
		return err;
	}

	err = delete_classifier_sport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier source port vector.\n");
		return err;
	}

	err = delete_classifier_dport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier dest port vector.\n");
		return err;
	}

	err = delete_classifier_icmp_type_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier icmp type vector.\n");
		return err;
	}

	err = delete_classifier_dev_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier device vector.\n");
		return err;
	}

	return EXIT_OK;
}

int delete_module(struct config *cfg)
{

	int err, len;
	int fw_map_fd;
	int index = 0;
	int module_index;
	int module_count;
	int module_map_fd;
	int index_map_fd;
	char map_path[PATH_MAX];
	struct module_info minfo;

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
		fprintf(stderr, "ERR: Reading modules info.\n");
		return EXIT_FAIL_BPF;
	}

	if (strcmp(minfo.module_name, cfg->module_name)) {
		fprintf(stderr, "ERR: Module name mismatch.\n");
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/firewall_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating firewall_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	fw_map_fd = bpf_obj_get(map_path);
	if (fw_map_fd < 0) {
		fprintf(stderr, "ERR: creating firewall_info map path.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(fw_map_fd, &index, &module_count)) {
		fprintf(stderr, "ERR: Reading firewall info.\n");
		return EXIT_FAIL_BPF;
	}

	int new_module_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32),
										sizeof(struct module_info), MAX_MODULE_ENTRIES, 0);
	if (new_module_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'modules_info' map\n");
		return EXIT_FAIL_BPF;
	}

	int new_index_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(char) * MAX_MODULE_NAME,
										sizeof(__u32), MAX_MODULE_ENTRIES, 0);
	if (new_module_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'modules_index' map\n");
		return EXIT_FAIL_BPF;
	}

	int new_prog_map_fd = bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY, sizeof(__u32),
										sizeof(__u32), MAX_MODULE_ENTRIES, 0);
	if (new_prog_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'firewall_modules' map\n");
		return EXIT_FAIL_BPF;
	}

	err = delete_classifier_vectors(cfg);
	if (err)
		return err;

	int i;
	for (i=0; i<module_count; i++) {
		if (i == module_index) continue;
		int new_index = i;
		if (i > module_index) new_index--;
		if (bpf_map_lookup_elem(module_map_fd, &i, &minfo)) {
			fprintf(stderr, "ERR: Reading old 'modules_info' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_update_elem(new_module_map_fd, &new_index, &minfo, 0)) {
			fprintf(stderr, "ERR: Updating new 'modules_info' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_update_elem(new_index_map_fd, &minfo.module_name, &new_index, 0)) {
			fprintf(stderr, "ERR: Updating new 'modules_index' map.\n");
			return EXIT_FAIL_BPF;
		}
		struct config loader_cfg = {
			.cmd		= ADD_MODULE,
			.new_index 	= new_index,
			.reuse_maps = 1,
		};

		strncpy(loader_cfg.module_new_name, minfo.module_name, MAX_MODULE_NAME);
		err = module_loader(&loader_cfg, new_prog_map_fd);
		if (err) {
			fprintf(stderr, "ERR: Reloading module '%s'.\n", minfo.module_name);
			return err;
		}
	}

	i = MAIN_MODULE;
	if (bpf_map_lookup_elem(module_map_fd, &i, &minfo)) {
		fprintf(stderr, "ERR: Reading old 'modules_info' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_update_elem(new_module_map_fd, &i, &minfo, 0)) {
		fprintf(stderr, "ERR: Updating new 'modules_info' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_update_elem(new_index_map_fd, &minfo.module_name, &i, 0)) {
		fprintf(stderr, "ERR: Updating new 'modules_index' map.\n");
		return EXIT_FAIL_BPF;
	}
	struct config loader_cfg = {
		.cmd		= ADD_MODULE,
		.new_index 	= i,
		.reuse_maps = 1,
	};

	strncpy(loader_cfg.module_new_name, minfo.module_name, MAX_MODULE_NAME);
	err = module_loader(&loader_cfg, new_prog_map_fd);
	if (err) {
		fprintf(stderr, "ERR: Reloading module '%s'.\n", minfo.module_name);
		return err;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'modules_info' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_module_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'modules_info' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_index", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_index map path.\n");
		return EXIT_FAIL_OPTION;
	}
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'modules_index' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_index_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'modules_index' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	loader_cfg.cmd = DELETE_MODULE;
	loader_cfg.index = module_index;

	strncpy(loader_cfg.module_name, cfg->module_name, MAX_MODULE_NAME);
	err = module_loader(&loader_cfg, -1);
	if (err) {
		fprintf(stderr, "ERR: Unload module '%s'.\n", cfg->module_name);
		return err;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/firewall_modules", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: Creating firewall modules map path.\n");
		return EXIT_FAIL_OPTION;
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'firewall_modules' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_prog_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'firewall_modules' map\n");
			return EXIT_FAIL_BPF;
		}
	}	

	module_count = module_count - 1;
	if(bpf_map_update_elem(fw_map_fd, &index, &module_count, 0)) {
		fprintf(stderr, "ERR: Updating firewall info.\n");
		return EXIT_FAIL_BPF;
	}

	err = fw_loader(1);
	if (err) {
		fprintf(stderr, "ERR: Reloading classifier.\n");
		return err;
	}
	return EXIT_OK;
}

int insert_classifier_src_ip_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 ipv4_key, ipv4_prev;
	struct in6_addr ipv6_key, ipv6_prev;
	union ipv4_lpm_key ipv4_lpm_key, ipv4_lpm_prev;
	union ipv6_lpm_key ipv6_lpm_key, ipv6_lpm_prev;
	struct class_vector vector;
	struct class_lpm_value lpm_val;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv4_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv4_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv4_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_prev = ipv4_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_prev, &ipv4_key) == 0) {

			if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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
								sizeof(struct class_lpm_value), MAX_MODULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv4_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv4_lpm_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv4_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_lpm_prev = ipv4_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_lpm_prev, &ipv4_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
				shift_right_class_vector(cfg->index, &lpm_val.vector);
				printf("%016llx\n", lpm_val.vector.word[0]);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv6_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv6_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv6_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_prev = ipv6_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_prev, &ipv6_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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
								sizeof(struct class_lpm_value), MAX_MODULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'src_ipv6_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/src_ipv6_lpm_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'src_ipv6_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_lpm_prev = ipv6_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_lpm_prev, &ipv6_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
				shift_right_class_vector(cfg->index, &lpm_val.vector);
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

int insert_classifier_dst_ip_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 ipv4_key, ipv4_prev;
	struct in6_addr ipv6_key, ipv6_prev;
	union ipv4_lpm_key ipv4_lpm_key, ipv4_lpm_prev;
	union ipv6_lpm_key ipv6_lpm_key, ipv6_lpm_prev;
	struct class_vector vector;
	struct class_lpm_value lpm_val;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv4_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv4_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv4_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_prev = ipv4_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_prev, &ipv4_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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
								sizeof(struct class_lpm_value), MAX_MODULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv4_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv4_lpm_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv4_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv4_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv4_lpm_prev = ipv4_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv4_lpm_prev, &ipv4_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv4_lpm_key, &lpm_val) >= 0) {
				shift_right_class_vector(cfg->index, &lpm_val.vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv6_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv6_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv6_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_prev = ipv6_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_prev, &ipv6_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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
								sizeof(struct class_lpm_value), MAX_MODULE_ENTRIES, BPF_F_NO_PREALLOC);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dst_ipv6_lpm_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dst_ipv6_lpm_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &lpm_val.vector);
			err = bpf_map_update_elem(new_map_fd, &ipv6_lpm_key, &lpm_val, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dst_ipv6_lpm_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		ipv6_lpm_prev = ipv6_lpm_key;

		while (bpf_map_get_next_key(map_fd, &ipv6_lpm_prev, &ipv6_lpm_key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &ipv6_lpm_key, &lpm_val) >= 0) {
				shift_right_class_vector(cfg->index, &lpm_val.vector);
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

int insert_classifier_sport_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u16 key, prev_key;
	struct class_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'tcp_sport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/tcp_sport_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'tcp_sport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'udp_sport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/udp_sport_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'udp_sport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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

int insert_classifier_dport_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u16 key, prev_key;
	struct class_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'tcp_dport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/tcp_dport_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'tcp_dport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'udp_dport_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/udp_dport_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'udp_dport_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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

int insert_classifier_icmp_type_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u8 key, prev_key;
	struct class_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u8),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'icmp_type_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/icmp_type_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'icmp_type_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'icmpv6_type_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/icmpv6_type_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'icmpv6_type_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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

int insert_classifier_dev_vector(struct config *cfg) {
	int err, len;
	int map_fd, new_map_fd;
	char map_path[PATH_MAX];
	__u32 key, prev_key;
	struct class_vector vector;

	new_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u32),
								sizeof(struct class_vector), MAX_MODULE_ENTRIES, 0);
	if (new_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'dev_vector' map.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/dev_vector", pin_basedir);
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
			shift_right_class_vector(cfg->index, &vector);
			err = bpf_map_update_elem(new_map_fd, &key, &vector, 0);
			if (err) {
				fprintf(stderr, "ERR: Updating new 'dev_vector' map.\n");
				return EXIT_FAIL_BPF;
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(map_fd, &key, &vector) >= 0) {
				shift_right_class_vector(cfg->index, &vector);
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

int insert_classifier_vectors(struct config *cfg) {
	int err;
	err = insert_classifier_src_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier src ip vector.\n");
		return err;
	}

	err = insert_classifier_dst_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier dst ip vector.\n");
		return err;
	}

	err = insert_classifier_sport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier source port vector.\n");
		return err;
	}

	err = insert_classifier_dport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier dest port vector.\n");
		return err;
	}

	err = insert_classifier_icmp_type_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier icmp type vector.\n");
		return err;
	}

	err = insert_classifier_dev_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating classifier device vector.\n");
		return err;
	}

	err = set_classifier_vectors(cfg, 1);
	if (err)
		return err;

	return EXIT_OK;
}

int insert_module(struct config *cfg)
{

	int err, len;
	int fw_map_fd;
	int index = 0;
	int module_index;
	int module_count;
	int module_map_fd;
	int index_map_fd;
	char map_path[PATH_MAX];
	struct module_info minfo;
	cfg->new_index = cfg->index;

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

	if (!bpf_map_lookup_elem(index_map_fd, &cfg->module_new_name, &module_index)) {
		if (module_index >= 0) {
			fprintf(stderr, "ERR: Module '%s' existed.\n", cfg->module_new_name);
			return EXIT_FAIL_OPTION;
		}
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


	len = snprintf(map_path, PATH_MAX, "%s/classifier/firewall_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating firewall_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	fw_map_fd = bpf_obj_get(map_path);
	if (fw_map_fd < 0) {
		fprintf(stderr, "ERR: creating firewall_info map path.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(fw_map_fd, &index, &module_count)) {
		fprintf(stderr, "ERR: Reading firewall info.\n");
		return EXIT_FAIL_BPF;
	}

	if (module_count >= MAX_MODULE) {
		fprintf(stderr, "ERR: Firewall has reach maximum amount of module.");
		return EXIT_FAIL_OPTION;
	}

	if (cfg->index >= module_count) {
		printf("WARN: Firewall has only %d modules. This rule would be appended to module instead.\n", module_count);
		err = add_rule(cfg, 0);
		return err;
	}

	if (cfg->index < 0 || cfg->index >= MAX_MODULE) {
		fprintf(stderr, "ERR: Invalid rule index (index=%d).\n", cfg->index);
		return EXIT_FAIL_OPTION;
	}

	int new_module_map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32),
										sizeof(struct module_info), MAX_MODULE_ENTRIES, 0);
	if (new_module_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'modules_info' map\n");
		return EXIT_FAIL_BPF;
	}

	int new_index_map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(char) * MAX_MODULE_NAME,
										sizeof(__u32), MAX_MODULE_ENTRIES, 0);
	if (new_module_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'modules_index' map\n");
		return EXIT_FAIL_BPF;
	}

	int new_prog_map_fd = bpf_create_map(BPF_MAP_TYPE_PROG_ARRAY, sizeof(__u32),
										sizeof(__u32), MAX_MODULE_ENTRIES, 0);
	if (new_prog_map_fd < 0) {
		fprintf(stderr, "ERR: Creating new 'firewall_modules' map\n");
		return EXIT_FAIL_BPF;
	}

	err = insert_classifier_vectors(cfg);
	if (err)
		return err;

	int i;
	for (i=module_count-1; i>=0; i--) {
		int new_index = i;
		if (i >= module_index) new_index++;
		if (bpf_map_lookup_elem(module_map_fd, &i, &minfo)) {
			fprintf(stderr, "ERR: Reading old 'modules_info' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_update_elem(new_module_map_fd, &new_index, &minfo, 0)) {
			fprintf(stderr, "ERR: Updating new 'modules_info' map.\n");
			return EXIT_FAIL_BPF;
		}
		if (bpf_map_update_elem(new_index_map_fd, &minfo.module_name, &new_index, 0)) {
			fprintf(stderr, "ERR: Updating new 'modules_index' map.\n");
			return EXIT_FAIL_BPF;
		}
		struct config loader_cfg = {
			.cmd		= ADD_MODULE,
			.new_index 	= new_index,
			.reuse_maps = 1,
		};

		strncpy(loader_cfg.module_new_name, minfo.module_name, MAX_MODULE_NAME);
		err = module_loader(&loader_cfg, new_prog_map_fd);
		if (err) {
			fprintf(stderr, "ERR: Reloading module '%s'.\n", minfo.module_name);
			return err;
		}

		if (i == cfg->index) {

			struct module_info new_minfo = {
				.key	= cfg->rule_key,
				.operating	= 1,
				.rule_count	= 0,
			};

			strncpy(new_minfo.module_name, cfg->module_new_name, MAX_MODULE_NAME);

			if (bpf_map_update_elem(new_module_map_fd, &i, &new_minfo, 0)) {
				fprintf(stderr, "ERR: Updating new 'modules_info' map.\n");
				return EXIT_FAIL_BPF;
			}
			if (bpf_map_update_elem(new_index_map_fd, &new_minfo.module_name, &i, 0)) {
				fprintf(stderr, "ERR: Updating new 'modules_index' map.\n");
				return EXIT_FAIL_BPF;
			}
			struct config loader_cfg = {
				.cmd		= ADD_MODULE,
				.new_index 	= i,
				.reuse_maps = 0,
			};

			strncpy(loader_cfg.module_new_name, new_minfo.module_name, MAX_MODULE_NAME);
			err = module_loader(&loader_cfg, new_prog_map_fd);
			if (err) {
				fprintf(stderr, "ERR: Loading module '%s'.\n", minfo.module_name);
				return err;
			}

		}
	}

	i = MAIN_MODULE;
	if (bpf_map_lookup_elem(module_map_fd, &i, &minfo)) {
		fprintf(stderr, "ERR: Reading old 'modules_info' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_update_elem(new_module_map_fd, &i, &minfo, 0)) {
		fprintf(stderr, "ERR: Updating new 'modules_info' map.\n");
		return EXIT_FAIL_BPF;
	}
	if (bpf_map_update_elem(new_index_map_fd, &minfo.module_name, &i, 0)) {
		fprintf(stderr, "ERR: Updating new 'modules_index' map.\n");
		return EXIT_FAIL_BPF;
	}
	struct config loader_cfg = {
		.cmd		= ADD_MODULE,
		.new_index 	= i,
		.reuse_maps = 1,
	};

	strncpy(loader_cfg.module_new_name, minfo.module_name, MAX_MODULE_NAME);
	err = module_loader(&loader_cfg, new_prog_map_fd);
	if (err) {
		fprintf(stderr, "ERR: Reloading module '%s'.\n", minfo.module_name);
		return err;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_info map path.\n");
		return EXIT_FAIL_OPTION;
	}
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'modules_info' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_module_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'modules_info' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/modules_index", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating modules_index map path.\n");
		return EXIT_FAIL_OPTION;
	}
	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'modules_index' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_index_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'modules_index' map\n");
			return EXIT_FAIL_BPF;
		}
	}

	struct config policy_cfg = {
		.rule_key	= {
			.AF			= 0,
			.src_ipv4	= 0x00000000,
			.dst_ipv4	= 0x00000000,
			.src_ipv6	= IN6ADDR_ANY_INIT,
			.dst_ipv6	= IN6ADDR_ANY_INIT,
			.src_ipv4_lpm = { },
			.dst_ipv4_lpm = { },
			.src_ipv6_lpm = { },
			.dst_ipv6_lpm = { },
			.proto		= 255,
			.sport		= 0,
			.dport		= 0,
			.icmp_type	= 255,
			.ifindex	= 0,
		},
		.rule_action = cfg->rule_action,
	};

	strncpy(policy_cfg.module_name, cfg->module_new_name, MAX_MODULE_NAME);

	err = add_rule(&policy_cfg, 1);
	if (err) {
		fprintf(stderr, "ERR: Initialize %s policy.\n", policy_cfg.module_name);
		return err;
	}

	len = snprintf(map_path, PATH_MAX, "%s/classifier/firewall_modules", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: Creating firewall modules map path.\n");
		return EXIT_FAIL_OPTION;
	}

	if (remove(map_path)) {
		fprintf(stderr, "ERR: Removing previous 'firewall_modules' map\n");
		return EXIT_FAIL_OPTION;
	} else {
		if (bpf_obj_pin(new_prog_map_fd, map_path)) {
			fprintf(stderr, "ERR: Pinning new 'firewall_modules' map\n");
			return EXIT_FAIL_BPF;
		}
	}	

	module_count = module_count + 1;
	if(bpf_map_update_elem(fw_map_fd, &index, &module_count, 0)) {
		fprintf(stderr, "ERR: Updating firewall info.\n");
		return EXIT_FAIL_BPF;
	}

	err = fw_loader(1);
	if (err) {
		fprintf(stderr, "ERR: Reloading classifier.\n");
		return err;
	}
	return EXIT_OK;

}

int list_modules() {
	int len;
	int fw_map_fd;
	int index = 0;
	int module_index = 0;
	int module_count;
	int module_map_fd;
	int dev_map_fd;
	char map_path[PATH_MAX];
	struct module_info minfo;
	__u32 key, prev_key, val;

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


	len = snprintf(map_path, PATH_MAX, "%s/classifier/firewall_info", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating firewall_info map path.\n");
		return EXIT_FAIL_OPTION;
	}

	fw_map_fd = bpf_obj_get(map_path);
	if (fw_map_fd < 0) {
		fprintf(stderr, "ERR: creating firewall_info map path.\n");
		return EXIT_FAIL_BPF;
	}

	if (bpf_map_lookup_elem(fw_map_fd, &index, &module_count)) {
		fprintf(stderr, "ERR: Reading firewall info.\n");
		return EXIT_FAIL_BPF;
	}

	len = snprintf(map_path, PATH_MAX, "%s/operating_dev", pin_basedir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating operating_dev map path.\n");
		return EXIT_FAIL_OPTION;
	}

	dev_map_fd = bpf_obj_get(map_path);
	if (fw_map_fd < 0) {
		fprintf(stderr, "ERR: creating operating_dev map path.\n");
		return EXIT_FAIL_BPF;
	}

	printf("XDP Modular Firewall\n");
	printf("======================================================================================================\n");
	printf("Loaded Modules: %5d | Operating on: ", module_count);

	if (bpf_map_get_next_key(dev_map_fd, NULL, &key) == 0) {
		if (bpf_map_lookup_elem(dev_map_fd, &key, &val) >= 0) {
			char ifname[IF_NAMESIZE];
			if (if_indextoname(key, ifname) != NULL) {
				printf("%s", ifname);
			}
		}
		prev_key = key;

		while (bpf_map_get_next_key(dev_map_fd, &prev_key, &key) == 0) {
			if (bpf_map_lookup_elem(dev_map_fd, &key, &val) >= 0) {
				char ifname[IF_NAMESIZE];
				if (if_indextoname(key, ifname) != NULL) {
					printf(", %s", ifname);
				}
			}
			prev_key = key;
		}

	} else printf("-");
	printf("\n------------------------------------------------------------------------------------------------------\n");
	printf("MODULE NAME\tSOURCE\t\tDEST\t\tPROT\tDEV\t\t\t\tRX PKTS\t\tRX BYTES\n");

	for (module_index=0; module_index<module_count; module_index++) {
		if (bpf_map_lookup_elem(module_map_fd, &module_index, &minfo) >= 0) {
			printf("%-11s\t", minfo.module_name);
			print_rulekey(&minfo.key);
			printf("\n");
		}
	}

	module_index = MAIN_MODULE;
	if (bpf_map_lookup_elem(module_map_fd, &module_index, &minfo) >= 0) {
		printf("%-11s\t", minfo.module_name);
		print_rulekey(&minfo.key);
	}
	printf("\n");

	return EXIT_OK;
}

#endif