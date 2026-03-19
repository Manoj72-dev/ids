#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include "cli.h"
#include "capture.h"
#include "rules.h"
#include "config.h"

static char *trim_whitespace(char *text)
{
    char *end;

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }

    if (*text == '\0') {
        return text;
    }

    end = text + strlen(text) - 1;
    while (end > text && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return text;
}

static int parse_bool_value(const char *value)
{
    return strcasecmp(value, "1") == 0 ||
           strcasecmp(value, "true") == 0 ||
           strcasecmp(value, "yes") == 0 ||
           strcasecmp(value, "on") == 0;
}

void load_default_config(CLIOptions *opts)
{
    opts->packet_count = CAPTURE_DEFAULT_PACKET_COUNT;
    snprintf(opts->rule_file, sizeof(opts->rule_file), "%s", RULE_FILE_PATH);
}

int load_config_file(const char *path, CLIOptions *opts)
{
    FILE *file;
    char line[256];

    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *cursor;
        char *separator;
        char *key;
        char *value;

        cursor = trim_whitespace(line);
        if (*cursor == '\0' || *cursor == '#') {
            continue;
        }

        separator = strchr(cursor, '=');
        if (separator == NULL) {
            continue;
        }

        *separator = '\0';
        key = trim_whitespace(cursor);
        value = trim_whitespace(separator + 1);

        if (strcasecmp(key, "interface") == 0) {
            snprintf(opts->interface, sizeof(opts->interface), "%s", value);
        } else if (strcasecmp(key, "protocol") == 0) {
            snprintf(opts->protocol, sizeof(opts->protocol), "%s", value);
        } else if (strcasecmp(key, "packet_count") == 0) {
            opts->packet_count = atoi(value);
        } else if (strcasecmp(key, "verbose") == 0) {
            opts->verbose = parse_bool_value(value);
        } else if (strcasecmp(key, "log_packets") == 0) {
            opts->log_packets = parse_bool_value(value);
        } else if (strcasecmp(key, "rule_file") == 0) {
            snprintf(opts->rule_file, sizeof(opts->rule_file), "%s", value);
        }
    }

    fclose(file);
    return 1;
}
