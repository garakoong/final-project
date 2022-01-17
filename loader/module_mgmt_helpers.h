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
#include "../common/common_helpers.h"
#include "../common/common_libbpf.h"
#include "../common/classifier_structs.h"
#include "loader_helpers.h"
#include "rule_mgmt_helpers.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

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
	vector.word[target_word] |= (__u64)1 << target_bit;
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
		.operating = 0,
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

	err = module_loader(cfg);
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
			.ifindex	= 0,
		},
		.rule_action = cfg->rule_action,
	};

	strncpy(policy_cfg.module_name, cfg->module_new_name, MAX_MODULE_NAME);

	err = add_rule(&policy_cfg, 1);
	if (err) {
		fprintf(stderr, "ERR: Initialize module %s policy.\n", policy_cfg.module_name);
	}

	printf("Module %s successfully added to firewall at index %d.\n", cfg->module_new_name, cfg->new_index);
	return EXIT_OK;
}

#endif