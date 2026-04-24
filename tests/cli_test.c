#include <stdio.h>
#include <string.h>
#include "cli.h"

static int fail_test(const char *name)
{
    fprintf(stderr, "FAIL: %s\n", name);
    return 1;
}

int main(void)
{
    CLIOptions opts;
    char *argv[] = {
        "cids",
        "-i", "eth0",
        "-p", "tcp port 80 and host 10.0.0.5",
        "-f", "tests/rules_test.rules",
        "-n", "25",
        "--log-packets",
        NULL
    };
    int argc = 10;

    cli_options_init(&opts);

    if (!parse_cli(argc, argv, &opts)) {
        return fail_test("parse_cli");
    }

    if (strcmp(opts.interface, "eth0") != 0) {
        return fail_test("interface_option");
    }

    if (strcmp(opts.protocol, "tcp port 80 and host 10.0.0.5") != 0) {
        return fail_test("bpf_filter_option");
    }

    if (strcmp(opts.rule_file, "tests/rules_test.rules") != 0) {
        return fail_test("rule_file_option");
    }

    if (opts.packet_count != 25) {
        return fail_test("packet_count_option");
    }

    if (!opts.log_packets) {
        return fail_test("log_packets_flag");
    }

    if (!validate_cli(&opts)) {
        return fail_test("validate_cli");
    }

    printf("cli tests passed\n");
    return 0;
}
