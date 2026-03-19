#ifndef CLI_H
#define CLI_H

#define CLI_INTERFACE_MAX 32
#define CLI_PROTOCOL_MAX  10
#define CLI_PATH_MAX      128

typedef struct
{
    char interface[CLI_INTERFACE_MAX];
    int verbose;
    int log_packets;
    char protocol[CLI_PROTOCOL_MAX];
    char rule_file[CLI_PATH_MAX];
    int packet_count;

    int list_interfaces;
    int read_logs;
    int clear_logs;

    int daemon_mode;
    int stop_daemon;
    int show_status;

    int show_help;
    int show_version;

} CLIOptions;

void cli_options_init(CLIOptions *opts);
int parse_cli(int argc, char *argv[], CLIOptions *opts);
int validate_cli(CLIOptions *opts);
void print_help(void);
void print_version(void);
int list_interfaces(void);

#endif
