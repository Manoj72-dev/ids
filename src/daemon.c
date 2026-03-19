#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "capture.h"
#include "daemon.h"

static int write_pid_file(pid_t pid)
{
    FILE *file;

    file = fopen(CIDS_PID_FILE, "w");
    if (file == NULL) {
        fprintf(stderr, "Error: could not write PID file %s\n", CIDS_PID_FILE);
        return 0;
    }

    fprintf(file, "%ld\n", (long)pid);
    fclose(file);
    return 1;
}

static int read_pid_file(pid_t *pid)
{
    FILE *file;
    long value;

    file = fopen(CIDS_PID_FILE, "r");
    if (file == NULL) {
        return 0;
    }

    if (fscanf(file, "%ld", &value) != 1) {
        fclose(file);
        return 0;
    }

    fclose(file);
    *pid = (pid_t)value;
    return 1;
}

static void remove_pid_file(void)
{
    unlink(CIDS_PID_FILE);
}

static int process_is_running(pid_t pid)
{
    if (pid <= 0) {
        return 0;
    }

    if (kill(pid, 0) == 0) {
        return 1;
    }

    return errno != ESRCH ? 1 : 0;
}

static void rotate_daemon_log_if_needed(void)
{
    struct stat log_stat;

    if (stat(CIDS_DAEMON_LOG, &log_stat) == -1) {
        return;
    }

    if (log_stat.st_size < CIDS_DAEMON_LOG_MAX_BYTES) {
        return;
    }

    unlink(CIDS_DAEMON_LOG_ROTATED);
    rename(CIDS_DAEMON_LOG, CIDS_DAEMON_LOG_ROTATED);
}

static int redirect_standard_streams(void)
{
    int stdin_fd;
    int log_fd;

    rotate_daemon_log_if_needed();

    stdin_fd = open("/dev/null", O_RDONLY);
    if (stdin_fd == -1) {
        return 0;
    }

    log_fd = open(CIDS_DAEMON_LOG, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (log_fd == -1) {
        close(stdin_fd);
        return 0;
    }

    if (dup2(stdin_fd, STDIN_FILENO) == -1 ||
        dup2(log_fd, STDOUT_FILENO) == -1 ||
        dup2(log_fd, STDERR_FILENO) == -1) {
        close(stdin_fd);
        close(log_fd);
        return 0;
    }

    close(stdin_fd);
    close(log_fd);
    return 1;
}

int start_cids_daemon(const char *interface_name, const char *protocol, int packet_count,
                      int verbose, int log_packets, const char *rule_file)
{
    pid_t pid;
    pid_t existing_pid;

    if (interface_name == NULL || interface_name[0] == '\0') {
        fprintf(stderr, "Error: --daemon requires -i <iface>.\n");
        return 1;
    }

    if (read_pid_file(&existing_pid) && process_is_running(existing_pid)) {
        fprintf(stderr, "Error: daemon is already running with PID %ld.\n", (long)existing_pid);
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Error: fork failed.\n");
        return 1;
    }

    if (pid > 0) {
        printf("CIDS daemon started with PID %ld\n", (long)pid);
        return 0;
    }

    if (setsid() == -1) {
        exit(1);
    }

    if (chdir(".") == -1) {
        exit(1);
    }

    umask(022);

    if (!redirect_standard_streams()) {
        exit(1);
    }

    if (!write_pid_file(getpid())) {
        exit(1);
    }

    if (open_interface(interface_name, protocol, packet_count, verbose, 1,
                       log_packets, rule_file) != 0) {
        remove_pid_file();
        exit(1);
    }

    remove_pid_file();
    return 0;
}

int stop_cids_daemon(void)
{
    pid_t pid;

    if (!read_pid_file(&pid)) {
        printf("CIDS daemon is not running.\n");
        return 0;
    }

    if (!process_is_running(pid)) {
        remove_pid_file();
        printf("CIDS daemon is not running.\n");
        return 0;
    }

    if (kill(pid, SIGTERM) == -1) {
        fprintf(stderr, "Error: could not stop daemon PID %ld.\n", (long)pid);
        return 1;
    }

    remove_pid_file();
    printf("Stopped CIDS daemon PID %ld\n", (long)pid);
    return 0;
}

int show_cids_daemon_status(void)
{
    pid_t pid;

    if (!read_pid_file(&pid) || !process_is_running(pid)) {
        printf("CIDS daemon is not running.\n");
        return 0;
    }

    printf("CIDS daemon is running with PID %ld\n", (long)pid);
    return 0;
}
