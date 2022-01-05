#ifndef __CLASSIFIER_STRUCTS_H
#define __CLASSIFIER_STRUCTS_H

#include "firewall_common.h"

struct module_info {
    char module_name[MAX_MODULE_NAME];
    __u32 rule_count;
    __u8 operating;
    struct rule_key key;
};

#endif