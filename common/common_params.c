#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP_FLAGS_* depend on kernel-headers installed */
#include <linux/if_xdp.h>
#include <arpa/inet.h>
#include <linux/in6.h>

#include "common_params.h"
#include "firewall_common.h"

int verbose = 1;

#define BUFSIZE 30

__u16 swapendian16(__u16 num) {
    return (num>>8) | (num<<8);
}

void _print_options(const struct option_wrapper *long_options, bool required)
{
	int i, pos;
	char buf[BUFSIZE];

	for (i = 0; long_options[i].option.name != 0; i++) {
		if (long_options[i].required != required)
			continue;

		if (long_options[i].option.val > 64) /* ord('A') = 65 */
			printf(" -%c,", long_options[i].option.val);
		else
			printf("    ");
		pos = snprintf(buf, BUFSIZE, " --%s", long_options[i].option.name);
		if (long_options[i].metavar)
			snprintf(&buf[pos], BUFSIZE-pos, " %s", long_options[i].metavar);
		printf("%-22s", buf);
		printf("  %s", long_options[i].help);
		printf("\n");
	}
}

void usage(const char *prog_name, const char *doc,
		   const struct option_wrapper *long_options, bool full)
{
	printf("Usage: %s [options]\n", prog_name);

	if (!full) {
		printf("Use --help (or -h) to see full option list.\n");
		return;
	}

	printf("\nDOCUMENTATION:\n %s\n", doc);
	printf("Required options:\n");
	_print_options(long_options, true);
	printf("\n");
	printf("Other options:\n");
	_print_options(long_options, false);
	printf("\n");
}

int option_wrappers_to_options(const struct option_wrapper *wrapper,
				struct option **options)
{
	int i, num;
	struct option *new_options;
	for (i = 0; wrapper[i].option.name != 0; i++) {}
	num = i;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;
	for (i = 0; i < num; i++) {
		memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
	}

	*options = new_options;
	return 0;
}

void parse_cmdline_args(int argc, char **argv,
			const struct option_wrapper *options_wrapper,
						struct config *cfg, const char *doc)
{
	struct option *long_options;
	bool full_help = false;
	int longindex = 0;
	char *dest;
	char* buf;
	__u32 prefixlen;
	int isLPM;
	int opt;
	char ipa[INET6_ADDRSTRLEN];

	if (option_wrappers_to_options(options_wrapper, &long_options)) {
		fprintf(stderr, "Unable to malloc()\n");
		exit(EXIT_FAIL_OPTION);
	}

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hLA:a:D:d:I:i:E:e:M:m:S:F:C:O:o:n:Uqf:t:p:j:N:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'L':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = LOAD_FW;
			break;
		case 'A':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = ADD_MODULE;
			if (strlen(optarg) >= MAX_MODULE_NAME) {
				fprintf(stderr, "ERR: module name too long\n");
				goto error;
			}
			dest  = (char *)&cfg->module_new_name;
			strncpy(dest, optarg, MAX_MODULE_NAME);
			break;
		case 'a':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = ADD_RULE;
			if (strlen(optarg) >= MAX_MODULE_NAME) {
				fprintf(stderr, "ERR: module name too long\n");
				goto error;
			}
			dest  = (char *)&cfg->module_name;
			strncpy(dest, optarg, MAX_MODULE_NAME);
			break;
		case 'D':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = DELETE_MODULE;
			if (strlen(optarg) >= MAX_MODULE_NAME) {
				fprintf(stderr, "ERR: module name too long\n");
				goto error;
			}
			dest  = (char *)&cfg->module_name;
			strncpy(dest, optarg, MAX_MODULE_NAME);
			break;
		case 'd':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = DELETE_RULE;
			if (strlen(optarg) >= MAX_MODULE_NAME) {
				fprintf(stderr, "ERR: module name too long\n");
				goto error;
			}
			dest  = (char *)&cfg->module_name;
			strncpy(dest, optarg, MAX_MODULE_NAME);
			break;
		case 'I':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = INSERT_MODULE;
			break;
		case 'i':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = INSERT_RULE;
			if (strlen(optarg) >= MAX_MODULE_NAME) {
				fprintf(stderr, "ERR: module name too long\n");
				goto error;
			}
			dest  = (char *)&cfg->module_name;
			strncpy(dest, optarg, MAX_MODULE_NAME);
			break;
		case 'E':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = EDIT_MODULE;
			break;
		case 'e':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = EDIT_RULE;
			break;
		case 'M':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = MOVE_MODULE;
			break;
		case 'm':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = DELETE_RULE;
			break;
		case 'S':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = SHOW_FW_STATS;
			/* check module name, if not '-' cfg->cmd = SHOW_MODULE_STATS */
			break;
		case 'F':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = FLUSH_FW;
			/* check module name, if not '-' cfg->cmd = FLUSH_MODULE */
			break;
		case 'C':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = FLUSH_FW_STATS;
			/* check module name, if not '-' cfg->cmd = FLUSH_MODULE_STATS */
			break;
		case 'O':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = ACTIVATE_MODULE;
			break;
		case 'o':
			if (cfg->cmd != PRESERVED) {
				fprintf(stderr, "ERR: Too many command flags.");
				goto error;
			}
			cfg->cmd = DEACTIVATE_MODULE;
			break;
		case 'N':
			break;
		case 'n':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --networkif name too long\n");
				goto error;
			}
			cfg->ifname = (char *)&cfg->ifname_buf;
			strncpy(cfg->ifname, optarg, IF_NAMESIZE);
			cfg->ifindex = if_nametoindex(cfg->ifname);
			if (cfg->ifindex == 0) {
				fprintf(stderr,
					"ERR: --networkif name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			cfg->rule_key.ifindex = cfg->ifindex;
			break;
		case 'j':
			if (strcmp(optarg, "ACCEPT") == 0)
				cfg->rule_action = XDP_PASS;
			else if (strcmp(optarg, "REJECT") == 0)
				cfg->rule_action = XDP_DROP;
			else {
				fprintf(stderr, "ERR: Action not supported. (Only 'ACCEPT' and 'REJECT' is available.\n");
				goto error;
			}
			break;
		case 'U':
			cfg->cmd = UNLOAD_FW;
			break;
		case 'q':
			verbose = false;
			break;
		case 'p':
			if (strcmp(optarg, "tcp") == 0 || strcmp(optarg, "TCP") == 0 || atoi(optarg) == IPPROTO_TCP) {
				cfg->rule_key.proto = IPPROTO_TCP;
			} else if (strcmp(optarg, "udp") == 0 || strcmp(optarg, "UDP") == 0 || atoi(optarg) == IPPROTO_UDP) {
				cfg->rule_key.proto = IPPROTO_UDP;
			} else {
				fprintf(stderr, "ERR: Protocol not supported.\n");
				goto error;
			}
			break;
		case 1: /* --sport */
			cfg->rule_key.sport = swapendian16(atoi(optarg));
			if (cfg->rule_key.sport <= 0 || cfg->rule_key.sport > 65535) {
				fprintf(stderr, "ERR: Invalid source port number (%d).\n", cfg->rule_key.sport);
				goto error;
			}
			break;
		case 2: /* --dport */
			cfg->rule_key.dport = swapendian16(atoi(optarg));
			if (cfg->rule_key.dport <= 0 || cfg->rule_key.dport > 65535) {
				fprintf(stderr, "ERR: Invalid dest port number (%d).\n", cfg->rule_key.dport);
				goto error;
			}
			break;
		case 3: /* --index */
			cfg->index = atoi(optarg);
			break;
		case 4: /* --new-index */
			cfg->new_index = atoi(optarg);
			break;
		case 'f':
			prefixlen = -1;
			isLPM = 0;

			buf = strtok(optarg, "/");			// get ip address part
			strncpy(ipa, buf, INET6_ADDRSTRLEN);

			buf = strtok(NULL, "/");			// get prefix part
			if (buf != NULL) {
				prefixlen = atoi(buf);
				isLPM = 1;
			}
				
			if (strchr(ipa, ':')) {
				if (cfg->rule_key.AF != 0 && cfg->rule_key.AF != AF_INET6) {
					fprintf(stderr, "ERR: IP address family mismatch.\n");
					goto error;
				}

				if (isLPM) {
					if (prefixlen < 0 || prefixlen > 128) {
						fprintf(stderr, "ERR: Invalid prefix len (%d).\n", prefixlen);
						goto error;
					} else if (prefixlen == 128) isLPM = 0;
				}

				if (isLPM) {
					cfg->rule_key.src_ipv6_lpm.word[0] = prefixlen;
					if (inet_pton(AF_INET6, ipa, &cfg->rule_key.src_ipv6_lpm.word[1]) != 1) {
						fprintf(stderr, "ERR: Invalid ip address (%s).\n", ipa);
						goto error;
					}
				} else {
					if (inet_pton(AF_INET6, ipa, &cfg->rule_key.src_ipv6) != 1) {
						fprintf(stderr, "ERR: Invalid ip address (%s).\n", ipa);
						goto error;
					}
				}
				cfg->rule_key.AF = AF_INET6;
			} else {
				if (cfg->rule_key.AF != 0 && cfg->rule_key.AF != AF_INET) {
					fprintf(stderr, "ERR: IP address family mismatch.\n");
					goto error;
				}

				if (isLPM) {
					if (prefixlen < 0 || prefixlen > 32) {
						fprintf(stderr, "ERR: Invalid prefix len (%d).\n", prefixlen);
						goto error;
					} else if (prefixlen == 32) isLPM = 0;
				}

				if (isLPM) {
					cfg->rule_key.src_ipv4_lpm.word[0] = prefixlen;
					if (inet_pton(AF_INET, ipa, &cfg->rule_key.src_ipv4_lpm.word[1]) != 1) {
						fprintf(stderr, "ERR: Invalid ip address (%s).\n", ipa);
						goto error;
					}
				} else {
					if (inet_pton(AF_INET, ipa, &cfg->rule_key.src_ipv4) != 1) {
						fprintf(stderr, "ERR: Invalid ip address (%s).\n", ipa);
						goto error;
					}
				}
				cfg->rule_key.AF = AF_INET;
			}
			break;
		case 't':
			prefixlen = -1;
			isLPM = 0;

			buf = strtok(optarg, "/");			// get ip address part
			strncpy(ipa, buf, INET6_ADDRSTRLEN);

			buf = strtok(NULL, "/");			// get prefix part
			if (buf != NULL) {
				prefixlen = atoi(buf);
				isLPM = 1;
			}
				
			if (strchr(ipa, ':')) {
				if (cfg->rule_key.AF != 0 && cfg->rule_key.AF != AF_INET6) {
					fprintf(stderr, "ERR: IP address family mismatch.\n");
					goto error;
				}

				if (isLPM) {
					if (prefixlen < 0 || prefixlen > 128) {
						fprintf(stderr, "ERR: Invalid prefix len (%d).\n", prefixlen);
						goto error;
					} else if (prefixlen == 128) isLPM = 0;
				}

				if (isLPM) {
					cfg->rule_key.dst_ipv6_lpm.word[0] = prefixlen;
					if (inet_pton(AF_INET6, ipa, &cfg->rule_key.dst_ipv6_lpm.word[1]) != 1) {
						fprintf(stderr, "ERR: Invalid ip address (%s).\n", ipa);
						goto error;
					}
				} else {
					if (inet_pton(AF_INET6, ipa, &cfg->rule_key.dst_ipv6) != 1) {
						fprintf(stderr, "ERR: Invalid ip address (%s).\n", ipa);
						goto error;
					}
				}
				cfg->rule_key.AF = AF_INET6;
			} else {
				if (cfg->rule_key.AF != 0 && cfg->rule_key.AF != AF_INET) {
					fprintf(stderr, "ERR: IP address family mismatch.\n");
					goto error;
				}

				if (isLPM) {
					if (prefixlen < 0 || prefixlen > 32) {
						fprintf(stderr, "ERR: Invalid prefix len (%d).\n", prefixlen);
						goto error;
					} else if (prefixlen == 32) isLPM = 0;
				}

				if (isLPM) {
					cfg->rule_key.dst_ipv4_lpm.word[0] = prefixlen;
					if (inet_pton(AF_INET, ipa, &cfg->rule_key.src_ipv6_lpm.word[1]) != 1) {
						fprintf(stderr, "ERR: Invalid ip address (%s).\n", ipa);
						goto error;
					}
				} else {
					if (inet_pton(AF_INET, ipa, &cfg->rule_key.dst_ipv4) != 1) {
						fprintf(stderr, "ERR: Invalid ip address (%s).\n", ipa);
						goto error;
					}
				}
				cfg->rule_key.AF = AF_INET;
			}
			break;
		case 'h':
			full_help = true;
			/* fall-through */
		error:
		default:
			usage(argv[0], doc, options_wrapper, full_help);
			free(long_options);
			exit(EXIT_FAIL_OPTION);
		}
	}
	free(long_options);
}
