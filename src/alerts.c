#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include "alerts.h"

static void format_timestamp(char *buffer, size_t buffer_size)
{
    time_t now;
    struct tm *local_time;

    now = time(NULL);
    local_time = localtime(&now);
    if (local_time == NULL) {
        snprintf(buffer, buffer_size, "unknown-time");
        return;
    }

    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", local_time);
}

int append_alert_log(const RuleAlert *alert, const PacketInfo *info)
{
    FILE *file;
    char timestamp[32];

    file = fopen(CIDS_ALERTS_LOG, "a");
    if (file == NULL) {
        fprintf(stderr, "Error: could not open %s for writing: %s\n",
                CIDS_ALERTS_LOG, strerror(errno));
        return 1;
    }

    format_timestamp(timestamp, sizeof(timestamp));

    if (info->src_port != 0 || info->dst_port != 0) {
        fprintf(file,
                "[%s] ALERT sid=%d rule=%s proto=%s severity=%s iface=%s %s src=%s:%u dst=%s:%u\n",
                timestamp,
                alert->sid,
                alert->rule_name,
                alert->protocol,
                alert->severity,
                info->interface,
                alert->message,
                info->src_ip,
                info->src_port,
                info->dst_ip,
                info->dst_port);
    } else {
        fprintf(file,
                "[%s] ALERT sid=%d rule=%s proto=%s severity=%s iface=%s %s src=%s dst=%s\n",
                timestamp,
                alert->sid,
                alert->rule_name,
                alert->protocol,
                alert->severity,
                info->interface,
                alert->message,
                info->src_ip,
                info->dst_ip);
    }

    fclose(file);
    return 0;
}

int read_alert_log(void)
{
    FILE *file;
    char line[512];
    int found_lines;

    file = fopen(CIDS_ALERTS_LOG, "r");
    if (file == NULL) {
        printf("No stored alerts found.\n");
        return 0;
    }

    found_lines = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        fputs(line, stdout);
        found_lines = 1;
    }

    fclose(file);

    if (!found_lines) {
        printf("No stored alerts found.\n");
    }

    return 0;
}

int clear_alert_log(void)
{
    FILE *file;

    file = fopen(CIDS_ALERTS_LOG, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: could not clear %s: %s\n",
                CIDS_ALERTS_LOG, strerror(errno));
        return 1;
    }

    fclose(file);
    printf("Cleared stored alerts.\n");
    return 0;
}
