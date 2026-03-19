#ifndef CAPTURE_H
#define CAPTURE_H

#define CAPTURE_DEFAULT_PACKET_COUNT 100

int open_interface(const char *interface_name, const char *protocol, int packet_count,
                   int verbose, int daemon_mode, int log_packets, const char *rule_file);

#endif
