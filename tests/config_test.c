#include <stdio.h>
#include <string.h>
#include "config.h"

static int fail_test(const char *name)
{
    fprintf(stderr, "FAIL: %s\n", name);
    return 1;
}

int main(void)
{
    CLIOptions opts;

    memset(&opts, 0, sizeof(opts));
    load_default_config(&opts);

    if (!load_config_file("tests/config_test.conf", &opts)) {
        return fail_test("load_config_file");
    }

    if (strcmp(opts.interface, "eth1") != 0) {
        return fail_test("interface_value");
    }

    if (strcmp(opts.protocol, "tcp port 443") != 0) {
        return fail_test("protocol_value");
    }

    if (opts.packet_count != 50) {
        return fail_test("packet_count_value");
    }

    if (!opts.verbose) {
        return fail_test("verbose_value");
    }

    if (!opts.log_packets) {
        return fail_test("log_packets_value");
    }

    if (strcmp(opts.rule_file, "rules/cids.rules") != 0) {
        return fail_test("rule_file_value");
    }

    printf("config tests passed\n");
    return 0;
}
