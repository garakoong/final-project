#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <net/if.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/in6.h>
#include <stdbool.h>
#include "firewall_common.h"

enum CMD {
	PRESERVED = 0,
	LOAD_FW,
	UNLOAD_FW,
	SHOW_FW_STATS,
	ADD_MODULE,
	ACTIVATE_MODULE,
	DEACTIVATE_MODULE,
	DELETE_MODULE,
	INSERT_MODULE,
	EDIT_MODULE,
	MOVE_MODULE,
	SHOW_MODULE_STATS,
	ADD_RULE,
	DELETE_RULE,
	INSERT_RULE,
	EDIT_RULE,
	MOVE_RULE,
	FLUSH_MODULE_STATS,
	FLUSH_FW_STATS,
	FLUSH_MODULE,
	FLUSH_FW
};

struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IF_NAMESIZE];
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	int cmd;
	char module_name[MAX_MODULE_NAME];
	char module_new_name[MAX_MODULE_NAME];
	struct rule_key rule_key;
	int index;
	int new_index;
	int rule_action;
};

/* Defined in common_params.o */
extern int verbose;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40
#define MAX_CMD			(FLUSH_FW + 1)

#endif /* __COMMON_DEFINES_H */
