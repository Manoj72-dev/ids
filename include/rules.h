#ifndef RULES_H
#define RULES_H

#include <stddef.h>
#include "packet.h"

#define RULE_FILE_PATH "rules/cids.rules"
#define RULE_NAME_LEN   64
#define RULE_PROTO_NAME_LEN 16
#define RULE_SEVERITY_LEN 16
#define RULE_MSG_LEN    256
#define MAX_RULE_ALERTS 16

typedef struct
{
    int matched;
    int sid;
    char rule_name[RULE_NAME_LEN];
    char protocol[RULE_PROTO_NAME_LEN];
    char severity[RULE_SEVERITY_LEN];
    char message[RULE_MSG_LEN];
} RuleAlert;

int load_rules_file(const char *path);
void unload_rules_file(void);
void rule_alert_init(RuleAlert *alert);
size_t evaluate_rules(const PacketInfo *info, RuleAlert *alerts, size_t max_alerts);

#endif
