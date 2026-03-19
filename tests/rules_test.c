#include <stdio.h>
#include <string.h>
#include "packet.h"
#include "rules.h"

static int fail_test(const char *name)
{
    fprintf(stderr, "FAIL: %s\n", name);
    return 1;
}

int main(void)
{
    PacketInfo info;
    RuleAlert alerts[MAX_RULE_ALERTS];
    size_t count;

    if (load_rules_file("tests/rules_test.rules") <= 0) {
        return fail_test("load_rules_file");
    }

    packet_info_init(&info);
    snprintf(info.src_ip, sizeof(info.src_ip), "192.168.1.25");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "10.0.0.5");
    info.ip_protocol = 6;
    info.src_port = 443;
    info.dst_port = 80;
    info.tcp_flags = 0x02;

    count = evaluate_rules(&info, alerts, MAX_RULE_ALERTS);
    if (count != 3) {
        return fail_test("cidr_port_range_and_bidirectional_match_count");
    }

    if (strstr(alerts[0].rule_name, "#2001") == NULL &&
        strstr(alerts[1].rule_name, "#2001") == NULL &&
        strstr(alerts[2].rule_name, "#2001") == NULL) {
        return fail_test("cidr_rule_present");
    }

    packet_info_init(&info);
    snprintf(info.src_ip, sizeof(info.src_ip), "172.16.0.10");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "10.0.0.5");
    info.ip_protocol = 6;
    info.src_port = 5555;
    info.dst_port = 8080;
    info.tcp_flags = 0x02;

    count = evaluate_rules(&info, alerts, MAX_RULE_ALERTS);
    if (count != 1 || strstr(alerts[0].rule_name, "#2003") == NULL) {
        return fail_test("bidirectional_only_match");
    }

    packet_info_init(&info);
    snprintf(info.src_ip, sizeof(info.src_ip), "172.16.0.10");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "8.8.8.8");
    info.ip_protocol = 6;
    info.src_port = 5555;
    info.dst_port = 8080;
    info.tcp_flags = 0x02;

    count = evaluate_rules(&info, alerts, MAX_RULE_ALERTS);
    if (count != 0) {
        return fail_test("no_match_case");
    }

    packet_info_init(&info);
    snprintf(info.src_ip, sizeof(info.src_ip), "192.168.10.25");
    snprintf(info.dst_ip, sizeof(info.dst_ip), "8.8.8.8");
    info.ip_protocol = 6;
    info.src_port = 5555;
    info.dst_port = 443;
    info.tcp_flags = 0x02;

    count = evaluate_rules(&info, alerts, MAX_RULE_ALERTS);
    if (count != 0) {
        return fail_test("threshold_first_hit_should_not_trigger");
    }

    count = evaluate_rules(&info, alerts, MAX_RULE_ALERTS);
    if (count != 0) {
        return fail_test("threshold_second_hit_should_not_trigger");
    }

    count = evaluate_rules(&info, alerts, MAX_RULE_ALERTS);
    if (count != 1 || strstr(alerts[0].rule_name, "#2004") == NULL) {
        return fail_test("threshold_third_hit_should_trigger");
    }

    unload_rules_file();
    printf("rules tests passed\n");
    return 0;
}
