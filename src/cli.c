#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap.h>
#include "cli.h"
#include "capture.h"
#include "config.h"
#include "rules.h"

static void copy_arg(char *dst, size_t dst_size, const char *src)
{
    if (dst_size == 0) {
        return;
    }

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

void cli_options_init(CLIOptions *opts)
{
    memset(opts, 0, sizeof(*opts));
}

void print_help(void)
{
    printf("CIDS - Command Line Intrusion Detection System\n");
    printf("Usage: cids [options]\n\n");
    printf("Defaults are loaded from %s when present.\n\n", CIDS_CONFIG_FILE);
    printf("Core Monitoring\n");
    printf("  -i <iface>     Monitor interface\n");
    printf("  -n <count>     Number of packets to capture, use 0 for continuous mode (default: %d)\n",
           CAPTURE_DEFAULT_PACKET_COUNT);
    printf("  -v             Show packet details in foreground mode\n");
    printf("  --log-packets  Write packet summaries to cids.log in daemon mode\n");
    printf("  -p <proto>     Filter protocol\n\n");
    printf("System\n");
    printf("  -l             List interfaces\n");
    printf("  -r             Read stored alerts\n");
    printf("  -c             Clear stored alerts\n");
    printf("  --daemon       Run capture in the background (requires -i)\n");
    printf("  --stop         Stop daemon\n");
    printf("  --status       Show status\n");
    printf("  --version      Show version\n");
    printf("  -h             Help\n");
    printf("\nRule file default: %s\n", RULE_FILE_PATH);
}

void print_version(void)
{
    printf("CIDS version 1.0\n");
}

int list_interfaces(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces = NULL;
    pcap_if_t *current = NULL;
    int index = 1;

    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error: failed to list interfaces: %s\n", errbuf);
        return 1;
    }

    if (interfaces == NULL) {
        printf("No interfaces found.\n");
        return 0;
    }

    for (current = interfaces; current != NULL; current = current->next) {
        printf("%d. %s", index, current->name);
        if (current->description != NULL) {
            printf(" - %s", current->description);
        }
        printf("\n");
        index++;
    }

    pcap_freealldevs(interfaces);
    return 0;
}

int validate_cli(CLIOptions *opts)
{
    int actions = 0;
    int monitor_action = 0;

    monitor_action = (opts->interface[0] != '\0') || opts->daemon_mode;
    actions += monitor_action;
    actions += opts->list_interfaces;
    actions += opts->read_logs;
    actions += opts->clear_logs;
    actions += opts->stop_daemon;
    actions += opts->show_status;

    if (opts->protocol[0] != '\0' && opts->interface[0] == '\0') {
        fprintf(stderr, "Error: -p/--protocol requires -i <iface>.\n");
        return 0;
    }

    if (opts->daemon_mode && opts->interface[0] == '\0') {
        fprintf(stderr, "Error: --daemon requires -i <iface>.\n");
        return 0;
    }

    if (opts->packet_count < 0) {
        fprintf(stderr, "Error: packet count must be zero or greater.\n");
        return 0;
    }

    if (opts->daemon_mode && opts->stop_daemon) {
        fprintf(stderr, "Error: --daemon and --stop cannot be used together.\n");
        return 0;
    }

    if ((opts->show_help || opts->show_version) && actions > 0) {
        fprintf(stderr, "Error: help/version cannot be combined with action flags.\n");
        return 0;
    }

    if (!opts->show_help && !opts->show_version && actions == 0) {
        fprintf(stderr, "Error: no action provided. Use -h for help.\n");
        return 0;
    }

    if (actions > 1) {
        fprintf(stderr, "Error: choose one primary action at a time.\n");
        return 0;
    }

    return 1;
}

int parse_cli(int argc, char *argv[], CLIOptions *opts)
{
    int option;
    opterr = 0;
    optind = 1;

    static struct option long_options[] = {
        {"daemon", no_argument, 0, 'd'},
        {"count", required_argument, 0, 'n'},
        {"log-packets", no_argument, 0, 'P'},
        {"stop", no_argument, 0, 's'},
        {"status", no_argument, 0, 't'},
        {"protocol", required_argument, 0, 'p'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((option = getopt_long(argc, argv, "i:n:vp:lrcdstVh", long_options, NULL)) != -1) {
        switch (option) {
            case 'i':
                copy_arg(opts->interface, sizeof(opts->interface), optarg);
                break;
            case 'n':
                opts->packet_count = atoi(optarg);
                break;
            case 'v':
                opts->verbose = 1;
                break;
            case 'P':
                opts->log_packets = 1;
                break;
            case 'p':
                copy_arg(opts->protocol, sizeof(opts->protocol), optarg);
                break;
            case 'l':
                opts->list_interfaces = 1;
                break;
            case 'r':
                opts->read_logs = 1;
                break;
            case 'c':
                opts->clear_logs = 1;
                break;
            case 'd':
                opts->daemon_mode = 1;
                break;
            case 's':
                opts->stop_daemon = 1;
                break;
            case 't':
                opts->show_status = 1;
                break;
            case 'V':
                opts->show_version = 1;
                break;
            case 'h':
                opts->show_help = 1;
                break;
            case '?':
                if (optopt != 0) {
                    fprintf(stderr, "Error: option -%c requires a value or is invalid.\n", optopt);
                } else {
                    fprintf(stderr, "Error: unknown option.\n");
                }
                return 0;
            default:
                return 0;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Error: unexpected argument: %s\n", argv[optind]);
        return 0;
    }

    return 1;
}
