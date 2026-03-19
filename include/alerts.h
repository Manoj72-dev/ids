#ifndef ALERTS_H
#define ALERTS_H

#include "packet.h"
#include "rules.h"

#define CIDS_ALERTS_LOG "logs/alerts.log"

int append_alert_log(const RuleAlert *alert, const PacketInfo *info);
int read_alert_log(void);
int clear_alert_log(void);

#endif
