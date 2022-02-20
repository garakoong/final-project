#ifndef __MODULE_STRUCTS_H
#define __MODULE_STRUCTS_H

struct rule_info {
    struct rule_key rule_key;
    int action;
    int jmp_index;
};

#endif