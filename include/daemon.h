#ifndef DAEMON_H
#define DAEMON_H

#define CIDS_PID_FILE "logs/cids.pid"
#define CIDS_DAEMON_LOG "logs/cids.log"
#define CIDS_DAEMON_LOG_ROTATED "logs/cids.log.1"
#define CIDS_DAEMON_LOG_MAX_BYTES (5 * 1024 * 1024)

int start_cids_daemon(const char *interface_name, const char *protocol, int packet_count,
                      int verbose, int log_packets, const char *rule_file);
int stop_cids_daemon(void);
int show_cids_daemon_status(void);

#endif
