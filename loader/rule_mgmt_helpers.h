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

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

int add_src_ip_vector(struct config *cfg) {
	
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				vector.word[target_word] |= (__u64)1 << target_bit;

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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;

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

					lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				vector.word[target_word] |= (__u64)1 << target_bit;

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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;

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
						
					lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
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

int add_dst_ip_vector(struct config *cfg) {

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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				vector.word[target_word] |= (__u64)1 << target_bit;

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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;

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

					lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				vector.word[target_word] |= (__u64)1 << target_bit;

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
				int target_word = cfg->new_index / 64;
				int target_bit = 63 - (cfg->new_index % 64);
				lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;

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
						
					lpm_val.vector.word[target_word] |= (__u64)1 << target_bit;
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

int add_sport_vector(struct config *cfg) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct rule_vector vector;;

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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
			vector.word[target_word] |= (__u64)1 << target_bit;

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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
			vector.word[target_word] |= (__u64)1 << target_bit;

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

int add_dport_vector(struct config *cfg) {
	int len;
	int map_fd;
	char map_path[PATH_MAX];
	struct rule_vector vector;;

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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
			vector.word[target_word] |= (__u64)1 << target_bit;

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

			int target_word = cfg->new_index / 64;
			int target_bit = 63 - (cfg->new_index % 64);
			vector.word[target_word] |= (__u64)1 << target_bit;

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

int add_dev_vector(struct config *cfg) {
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
	
	int target_word = cfg->new_index / 64;
	int target_bit = 63 - (cfg->new_index % 64);
	vector.word[target_word] |= (__u64)1 << target_bit;
	if (bpf_map_update_elem(map_fd, &cfg->rule_key.ifindex, &vector, 0)) {
		fprintf(stderr, "ERR: Updating dev_vector map.\n");
		return EXIT_FAIL_BPF;
	}

	return EXIT_OK;
}

int add_vectors(struct config *cfg) {
	int err;
	err = add_src_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s src ip vector.\n", cfg->module_name);
		return err;
	}

	err = add_dst_ip_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s dst ip vector.\n", cfg->module_name);
		return err;
	}

	err = add_sport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s source port vector.\n", cfg->module_name);
		return err;
	}

	err = add_dport_vector(cfg);
	if (err) {
		fprintf(stderr, "ERR: Updating module %s dest port vector.\n", cfg->module_name);
		return err;
	}

	err = add_dev_vector(cfg);
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

		cfg->new_index = minfo.rule_count;
	} else cfg->new_index = POLICY_RULE;

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

	if (bpf_map_update_elem(rule_map_fd, &cfg->new_index, &rinfo, 0)) {
		fprintf(stderr, "ERR: Updating rules info.\n");
		return EXIT_FAIL_BPF;
	}

	err = add_vectors(cfg);
	if (err)
		return err;

	if (!isPolicy) {
		minfo.rule_count += 1;
		if (bpf_map_update_elem(module_map_fd, &module_index, &minfo, 0)) {
			fprintf(stderr, "ERR: Updating modules info.\n");
			return EXIT_FAIL_BPF;
		}
		printf("Rule successfully added to module %s at index %d.\n", cfg->module_name, cfg->new_index);
	}

	return EXIT_OK;
}

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

#endif