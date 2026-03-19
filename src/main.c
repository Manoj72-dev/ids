#include <stdio.h>
#include "../include/cli.h"
#include "../include/alerts.h"
#include "../include/capture.h"
#include "../include/config.h"
#include "../include/daemon.h"

int main(int argc, char *argv[])
{
    CLIOptions opts;

    cli_options_init(&opts);
    load_default_config(&opts);
    load_config_file(CIDS_CONFIG_FILE, &opts);

    if (!parse_cli(argc, argv, &opts)) {
        return 1;
    }

    if (!validate_cli(&opts)) {
        return 1;
    }

    if (opts.show_help) {
        print_help();
        return 0;
    }

    if (opts.show_version) {
        print_version();
    } else if (opts.list_interfaces) {
        return list_interfaces();
    } else if (opts.read_logs) {
        return read_alert_log();
    } else if (opts.clear_logs) {
        return clear_alert_log();
    } else if (opts.daemon_mode) {
        return start_cids_daemon(opts.interface, opts.protocol, opts.packet_count,
                                 opts.verbose, opts.log_packets, opts.rule_file);
    } else if (opts.stop_daemon) {
        return stop_cids_daemon();
    } else if (opts.show_status) {
        return show_cids_daemon_status();
    } else if (opts.interface[0] != '\0') {
        return open_interface(opts.interface, opts.protocol, opts.packet_count,
                              opts.verbose, 0, opts.log_packets, opts.rule_file);
    }

    return 0;
}
