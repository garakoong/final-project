/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP MODULAR FIREWALL\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --interface\n";

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

	{{"load",       no_argument,		NULL, 'L' },
	 "Load firewall, pin maps, and operate firewall on <ifname> if given.", "[-n <ifname>]"},

	{{"show",	required_argument,	NULL, 'S' },
	 "Show info of module <module name>. (if '-' is given, show firewall's info)", "<module name>"},

	{{"new-module",	required_argument,	NULL, 'N' },
	 "Add module <module name> to firewall.", "<module name> [options]"},

	{{"add-rule",	required_argument,	NULL, 'A' },
	 "Add rule to module <module name>.", "<module name> [options]"},

	{{"delete-module",	required_argument,	NULL, 'X' },
	 "Delete module <module name> from firewall.", "<module name>"},

	{{"delete-rule",	required_argument,	NULL, 'D' },
	 "Delete rule number <rule num> from module <module name>. (use --rule-num to define <rule num>)", "<module name>"},

	{{"insert",	required_argument,	NULL, 'I' },
	 "Insert module / rule at index <index>. (--index for module / --rule-num for rule)", "<module name>"},

	{{"rewrite",	required_argument,	NULL, 'R' },
	 "Rewrite module / rule at index <index>. (--index for module / --rule-num for rule)", "<module name>"},

	{{"policy",	required_argument,	NULL, 'P' },
	 "Set module <module name> policy. (use --j to define action)", "<module name>"},

	{{"interface",	required_argument,	NULL, 'i' },
	 "Operate on device <ifname>", "<ifname>"},

	{{"flush",	required_argument,	NULL, 'F' },
	 "Flush module <module name>. (if '-' is given, flush firewall)", "<module name>"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"sport",    required_argument,	NULL,  1  },
	 "Source port number", "<sport>"},

	{{"dport",    required_argument,	NULL,  2  },
	 "Destination port number", "<dport>"},

	{{"index",    required_argument,	NULL,  3  },
	 "Module index", "<index>"},

	{{"rule-num",    required_argument,	NULL,  4  },
	 "Rule number", "<rule num>"},

	{{"icmp-type",    required_argument,	NULL,  5  },
	 "ICMP packet type.", "<type>"},

	{{"jmp-index",    required_argument,	NULL,  6  },
	 "Jump index.", "<jump index>"},

	{{"activate",    required_argument,	NULL,  7  },
	 "Activate module <module name>.", "<module name>"},

	{{"deactivate",    required_argument,	NULL,  8  },
	 "Deactivate module <module name>.", "<module name>"},

	{{"new-name",    required_argument,	NULL,  9  },
	 "Module new name.", "<new name>"},

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
		.rule_num = -1,
		.module_index = -1,
		.jmp_index = -1,
	};

	memset(&cfg.rule_key.src_ipv4_lpm, 0, ipv4_lpm_key_size);
	memset(&cfg.rule_key.dst_ipv4_lpm, 0, ipv4_lpm_key_size);
	memset(&cfg.rule_key.src_ipv6_lpm, 0, ipv6_lpm_key_size);
	memset(&cfg.rule_key.dst_ipv6_lpm, 0, ipv6_lpm_key_size);
	
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	if (cfg.module_index >= 0 && cfg.rule_num >= 0) {
		fprintf(stderr, "ERR: Option --index and --rule-num can not be used together.\n");
		return EXIT_FAIL_OPTION;
	}

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
			err = root_loader(&cfg);
			if (err) {
				fprintf(stderr, "ERR: loading firewall.\n");
				return err;
			}
			memset(&cfg.progsec, 0, sizeof(cfg.progsec));
			cfg.rule_key.ifindex = 0;
			cfg.cmd = ADD_MODULE;
			strncpy(cfg.module_name, "MAIN", MAX_MODULE_NAME);
			cfg.rule_action = XDP_PASS;
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
			} else if (cfg.rule_action == XDP_REDIRECT && cfg.jmp_index < 0) {
				fprintf(stderr, "ERR: Jump index is not set. (--jmp-index option is required)\n");
				return EXIT_FAIL_OPTION;
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
			if (cfg.module_index < 0) {
				fprintf(stderr, "ERR: Module index is not set. (--index option is required.)\n");
				return EXIT_FAIL_OPTION;
			}
			if (cfg.rule_action == XDP_ABORTED) {
				printf("WARN: Module's policy is not set. Default is ACCEPT\n");
				cfg.rule_action = XDP_PASS;
			} else if (cfg.rule_action == XDP_REDIRECT && cfg.jmp_index < 0) {
				fprintf(stderr, "ERR: Jump index is not set. (--jmp-index option is required)\n");
				return EXIT_FAIL_OPTION;
			}

			err = insert_module(&cfg);
			if (err) {
				fprintf(stderr, "ERR: inserting firewall module.\n");
				return err;
			}
			break;
		case REWRITE_MODULE:
			err = rewrite_module(&cfg);
			if (err) {
				fprintf(stderr, "ERR: rewriting module %s.\n", cfg.module_name);
				return err;
			}
			break;
		case SET_POLICY:
			if (cfg.rule_action == XDP_ABORTED) {
				printf("WARN: Module's policy is not set. Default is ACCEPT\n");
				cfg.rule_action = XDP_PASS;
			} else if (cfg.rule_action == XDP_REDIRECT && cfg.jmp_index < 0) {
				fprintf(stderr, "ERR: Jump index is not set. (--jmp-index option is required)\n");
				return EXIT_FAIL_OPTION;
			}

			err = set_policy(&cfg);
			if (err) {
				fprintf(stderr, "ERR: setting module %s policy.\n", cfg.module_name);
				return err;
			}
			break;
		case FLUSH_MODULE:
			err = flush_module(&cfg);
			if (err) {
				fprintf(stderr, "ERR: flushing module %s.\n", cfg.module_name);
				return err;
			}
			break;
		case FLUSH_FW:
			err = flush_firewall(&cfg);
			if (err) {
				fprintf(stderr, "ERR: flushing firewall.\n");
				return err;
			}
			break;
		case RENAME_MODULE:
			if (strlen(cfg.module_new_name) <= 0) {
				fprintf(stderr, "ERR: Module new name is not set. (--new-name is required)\n");
				return EXIT_FAIL_OPTION;
			}
			err = rename_module(&cfg);
			if (err) {
				fprintf(stderr, "ERR: renaming module %s.", cfg.module_name);
				return err;
			}
			break;
		case ADD_RULE:
			if (cfg.rule_action == XDP_ABORTED) {
				fprintf(stderr, "ERR: Rule's action is not set. (-j option is required.)\n");
				return EXIT_FAIL_OPTION;
			} else if (cfg.rule_action == XDP_REDIRECT && cfg.jmp_index < 0) {
				fprintf(stderr, "ERR: Jump index is not set. (--jmp-index option is required)\n");
				return EXIT_FAIL_OPTION;
			}

			err = add_rule(&cfg, 0);
			if (err) {
				fprintf(stderr, "ERR: adding rule to module %s.\n", cfg.module_name);
				return err;
			}
			break;
		case DELETE_RULE:
			if (cfg.rule_num < 0) {
				fprintf(stderr, "ERR: Rule number is not set. (--rule-num option is required.)\n");
				return EXIT_FAIL_OPTION;
			}
			err = delete_rule(&cfg);
			if (err) {
				fprintf(stderr, "ERR: deleting rule from module %s.\n", cfg.module_name);
				return err;
			}
			break;
		case INSERT_RULE:
			if (cfg.rule_num < 0) {
				fprintf(stderr, "ERR: Rule number is not set. (--rule-num option is required.)\n");
				return EXIT_FAIL_OPTION;
			}
			if (cfg.rule_action == XDP_ABORTED) {
				fprintf(stderr, "ERR: Rule's action is not set. (-j option is required.)\n");
				return EXIT_FAIL_OPTION;
			} else if (cfg.rule_action == XDP_REDIRECT && cfg.jmp_index < 0) {
				fprintf(stderr, "ERR: Jump index is not set. (--jmp-index option is required)\n");
				return EXIT_FAIL_OPTION;
			}
			err = insert_rule(&cfg);
			if (err) {
				fprintf(stderr, "ERR: inserting rule to module %s at index %d.\n", cfg.module_name, cfg.rule_num);
				return err;
			}
			break;
		case REWRITE_RULE:
			if (cfg.rule_num < 0) {
				fprintf(stderr, "ERR: Rule number is not set. (--rule-num option is required.)\n");
				return EXIT_FAIL_OPTION;
			}
			if (cfg.rule_action == XDP_ABORTED) {
				printf("WARN: Rule action is not set. Default is ACCEPT\n");
				cfg.rule_action = XDP_PASS;
			} else if (cfg.rule_action == XDP_REDIRECT && cfg.jmp_index < 0) {
				fprintf(stderr, "ERR: Jump index is not set. (--jmp-index option is required)\n");
				return EXIT_FAIL_OPTION;
			}
			err = rewrite_rule(&cfg);
			if (err) {
				fprintf(stderr, "ERR: rewriting rule.\n");
				return err;
			}
			break;
		case ACTIVATE_MODULE:
		case DEACTIVATE_MODULE:
			err = change_module_status(&cfg);
			if (err) {
				fprintf(stderr, "ERR: changing module %s's status.\n", cfg.module_name);
				return err;
			}
			break;
		default:
			fprintf(stderr, "Command is required. Use -h option to see available command flags.\n");
			return EXIT_FAIL_OPTION;
	}

	return EXIT_OK;
}
