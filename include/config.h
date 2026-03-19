#ifndef CONFIG_H
#define CONFIG_H

#include "cli.h"

#define CIDS_CONFIG_FILE "config/cids.conf"

void load_default_config(CLIOptions *opts);
int load_config_file(const char *path, CLIOptions *opts);

#endif
