/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP MODULAR FIREWALL\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --networkif\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"load-fw",       no_argument,		NULL, 'L' },
	 "Load firewall, pin maps, and operate firewall on <ifname> if given.", "[-n <ifname>]"},

	{{"add-module",	required_argument,	NULL, 'A' },
	 "Add module <module name> to firewall.", "<module name> [options]"},

	{{"add-rule",	required_argument,	NULL, 'a' },
	 "Add rule to module <module name>.", "<module name> [options]"},

	{{"delete-module",	required_argument,	NULL, 'D' },
	 "Delete module <module name> from firewall.", "<module name>"},

	{{"delete-rule",	required_argument,	NULL, 'd' },
	 "Delete rule number <rule num> from module <module name>. (use --index to define <rule num>)", "<module name>"},

	{{"insert-module",	required_argument,	NULL, 'I' },
	 "Insert module <module name> to module number <module num> of firewall.", "<module name>"},

	{{"insert-rule",	required_argument,	NULL, 'i' },
	 "Insert rule as rule number <rule num> of module <module name>.", "<module name>"},

	{{"edit-module",	required_argument,	NULL, 'E' },
	 "Edit module <module name>.", "<module name> [options]"},

	{{"edit-rule",	required_argument,	NULL, 'e' },
	 "Edit rule <rule num> of module <module name>.", "<module name> [options]"},

	{{"networkif",	required_argument,	NULL, 'n' },
	 "Operate on device <ifname>", "<ifname>"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"sport",    required_argument,	NULL,  1  },
	 "Source port number", "<sport>"},

	{{"dport",    required_argument,	NULL,  2  },
	 "Destination port number", "<dport>"},

	{{"index",    required_argument,	NULL,  3  },
	 "Rule / Module index", "<index>"},

	{{"new-index",    required_argument,	NULL,  4  },
	 "Rule / Module new index", "<new-index>"},

	{{"icmp-type",    required_argument,	NULL,  5  },
	 "ICMP packet type.", "<type>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf/xdp-mfw";

#include "loader_helpers.h"
#include "module_mgmt_helpers.h"
#include "rule_mgmt_helpers.h"

int main(int argc, char **argv)
{
	int err;

	struct config cfg = {
		.ifindex	= -1,
		.cmd		= PRESERVED,
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
		.rule_action = XDP_ABORTED,
		.index = -1,
		.new_index = -1,
	};

	memset(&cfg.rule_key.src_ipv4_lpm, 0, ipv4_lpm_key_size);
	memset(&cfg.rule_key.dst_ipv4_lpm, 0, ipv4_lpm_key_size);
	memset(&cfg.rule_key.src_ipv6_lpm, 0, ipv6_lpm_key_size);
	memset(&cfg.rule_key.dst_ipv6_lpm, 0, ipv6_lpm_key_size);
	
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if ((cfg.rule_key.proto != IPPROTO_TCP && cfg.rule_key.proto != IPPROTO_UDP) &&
		(cfg.rule_key.sport != 0 || cfg.rule_key.dport != 0)) {
		fprintf(stderr, "ERR: Required -p option (tcp/udp protocol).\n");
		return EXIT_FAIL_OPTION;
	}
	if ((cfg.rule_key.proto != IPPROTO_ICMP && cfg.rule_key.proto != IPPROTO_ICMPV6) &&
		cfg.rule_key.icmp_type != 255) {
		fprintf(stderr, "ERR: Required -p option (icmp/icmpv6 protocol).\n");
		return EXIT_FAIL_OPTION;
	} else if (cfg.rule_key.proto == IPPROTO_ICMPV6) {
		if (cfg.rule_key.icmp_type == ICMP_ECHO) cfg.rule_key.icmp_type = ICMPV6_ECHO_REQUEST;
		else if (cfg.rule_key.icmp_type == ICMP_ECHOREPLY) cfg.rule_key.icmp_type = ICMPV6_ECHO_REPLY;
	}

	switch(cfg.cmd) {
		case LOAD_FW:
			strncpy(cfg.module_new_name, "MAIN", MAX_MODULE_NAME);
			cfg.rule_action = XDP_PASS;
			err = root_loader(&cfg);
			if (err) {
				fprintf(stderr, "ERR: loading firewall.\n");
				return err;
			}
			memset(&cfg.progsec, 0, sizeof(cfg.progsec));
			cfg.rule_key.ifindex = 0;
			cfg.cmd = ADD_MODULE;
			err = add_module(&cfg, 1);
			if (err) {
				fprintf(stderr, "ERR: adding Module 'MAIN'.\n");
				return err;
			}
			break;
		case UNLOAD_FW:
			err = root_loader(&cfg);
			if (err) {
				fprintf(stderr, "ERR: unloading firewall.\n");
			}
			break;
		case SHOW_FW_STATS:
			list_modules();
			break;
		case SHOW_MODULE_STATS:
			list_rules(&cfg);
			break;
		case ADD_MODULE:
			if (cfg.rule_action == XDP_ABORTED) {
				printf("WARN: Module's policy is not set. Default is ACCEPT\n");
				cfg.rule_action = XDP_PASS;
			}

			err = add_module(&cfg, 0);
			if (err) {
				fprintf(stderr, "ERR: adding firewall module.\n");
				return err;
			}
			break;
		case DELETE_MODULE:
			err = delete_module(&cfg);
			if (err) {
				fprintf(stderr, "ERR: deleting firewall module.\n");
				return err;
			}
			break;
		case INSERT_MODULE:
			if (cfg.index < 0) {
				fprintf(stderr, "ERR: Module index is not set. (--index option is required.)\n");
				return EXIT_FAIL_OPTION;
			}

			err = insert_module(&cfg);
			if (err) {
				fprintf(stderr, "ERR: inserting firewall module.\n");
				return err;
			}
			break;
		case ADD_RULE:
			if (cfg.rule_action == XDP_ABORTED) {
				fprintf(stderr, "ERR: Rule's action is not set. (-j option is required.)\n");
				return EXIT_FAIL_OPTION;
			}

			err = add_rule(&cfg, 0);
			if (err) {
				fprintf(stderr, "ERR: adding rule to module %s.\n", cfg.module_name);
				return err;
			}
			break;
		case DELETE_RULE:
			if (cfg.index < 0) {
				fprintf(stderr, "ERR: Rule index is not set. (--index option is required.)\n");
				return EXIT_FAIL_OPTION;
			}
			err = delete_rule(&cfg);
			if (err) {
				fprintf(stderr, "ERR: deleting rule from module %s.\n", cfg.module_name);
				return err;
			}
			break;
		case INSERT_RULE:
			if (cfg.index < 0) {
				fprintf(stderr, "ERR: Rule index is not set. (--index option is required.)\n");
				return EXIT_FAIL_OPTION;
			}
			err = insert_rule(&cfg);
			if (err) {
				fprintf(stderr, "ERR: inserting rule to module %s at index %d.\n", cfg.module_name, cfg.new_index);
				return err;
			}
			break;
		default:
			fprintf(stderr, "Command is required. Use -h option to see available command flags.\n");
			return EXIT_FAIL_OPTION;
	}

	return EXIT_OK;
}
